using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.X509.Store;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Cms;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Utilities.IO.Pem;

using OpenSsl = Org.BouncyCastle.OpenSsl;

namespace Emulamer.Utils
{
    public class Apkifier : IDisposable, IApkFileIO
    {
        private SHA1 _sha = SHA1Managed.Create();
        private UTF8Encoding _encoding = new UTF8Encoding(false);
        protected string _filename;
        protected ZipArchive _archive;
        private bool _sign;
        private string _pemData;
        private bool _hasChanges;
        private bool _readOnly;
        /// <summary>
        /// Returns true if changes have been made
        /// </summary>
        public bool HasChanges
        {
            get { return _hasChanges; }
        }

        /// <summary>
        /// Returns the PEM data used to sign the APK
        /// </summary>
        public string PemData
        {
            get
            {
                return _pemData;
            }
        }
        public bool IsReadOnly
        {
            get
            { return _readOnly; }
        }

        /// <summary>
        /// Creates a new instance of Apkifier
        /// </summary>
        /// <param name="filename">The full path to the APK file</param>
        /// <param name="sign">True to sign the APK when Apkifier is disposed.</param>
        /// <param name="x509certificateData">The PEM data of the certificate to use with both public and private keys.  If null, a new, automatically created certificate will be used.</param>
        public Apkifier(string filename, bool sign = true, string pemCertificateData = null, bool readOnly = false)
        {
            _filename = filename;
            _sign = sign;
            _readOnly = readOnly;

            if (pemCertificateData != null)
            {
                _pemData = pemCertificateData;
                //test that the certificate loads before going further
                AsymmetricKeyParameter pk;
                LoadCert(_pemData, out pk);
            }
            else
            {
                _pemData = GenerateNewCertificatePEM();
            }
            if (_readOnly)
                _archive = ZipFile.OpenRead(_filename);
            else
                _archive = ZipFile.Open(_filename, ZipArchiveMode.Update);
            
        }



        public void LoadCert(byte[] certData)
        {
            using (MemoryStream ms = new MemoryStream(certData))
            {
                Pkcs12Store store = new Pkcs12Store(ms, new char[0]);
            }
        }

        /// <summary>
        /// Checks if a file exists within the APK
        /// </summary>
        /// <param name="targetPath">The full path and filename</param>
        public virtual bool FileExists(string targetPath)
        {
            return GetEntry(targetPath) != null;
        }

        private ZipArchiveEntry GetEntry(string filename)
        {
            foreach (var e in _archive.Entries)
            {
                if (e.FullName.ToLower() == filename.ToLower())
                    return e;
            }
            return null;
        }

        /// <summary>
        /// Writes the contents of a stream to a file in the APK
        /// </summary>
        /// <param name="fileData">The stream of data to store in the file</param>
        /// <param name="targetPath">The full target path and filename within the APK</param>
        /// <param name="overwrite">True to allow overwriting an existing file</param>
        /// <param name="compress">True to compress the data.</param>
        public virtual void Write(Stream fileData, string targetPath, bool overwrite = false, bool compress = true)
        {
            _hasChanges = true;
            using (var stream = GetWriteStream(targetPath, overwrite, compress))
            {
                fileData.CopyTo(stream);
            }
        }

        /// <summary>
        /// Writes a file to the APK from a source file
        /// </summary>
        /// <param name="inputFileName">The name of the source file</param>
        /// <param name="targetPath">The full target path and filename within the APK</param>
        /// <param name="overwrite">True to allow overwriting an existing file</param>
        /// <param name="compress">True to compress the data</param>
        public virtual void Write(string inputFileName, string targetPath, bool overwrite = false, bool compress = true)
        {
            _hasChanges = true;
            if (overwrite )
            {
                var entry = _archive.GetEntry(targetPath);
                if (entry != null)
                    entry.Delete();
            }
            _archive.CreateEntryFromFile(inputFileName, targetPath, compress ? CompressionLevel.Optimal : CompressionLevel.NoCompression);
            //using (FileStream fs = File.Open(inputFileName, FileMode.Open, FileAccess.Read))
            //{
            //    Write(fs, targetPath, overwrite, compress);
            //}
        }

        /// <summary>
        /// Gets a writeable stream for the specified file
        /// </summary>
        /// <param name="targetPath">The full target path and filename within the APK</param>
        /// <param name="overwrite">True to allow overwriting an existing file</param>
        /// <param name="compress">True to compress the data</param>
        /// <returns></returns>
        public Stream GetWriteStream(string targetPath, bool overwrite = false, bool compress = true)
        {
            _hasChanges = true;
            var entry = GetEntry(targetPath);
            if (entry != null)
            {
                if (!overwrite)
                    throw new InvalidOperationException("File at the target path already exists.");
                else
                    entry.Delete();
            }
            //delete and recreate in case compression mode has changed
            entry = _archive.CreateEntry(targetPath, compress ? CompressionLevel.Optimal : CompressionLevel.NoCompression);
            return entry.Open();
        }

        private static bool FilePatternMatch(string filename, string pattern)
        {
            Regex mask = new Regex(pattern.Replace(".", "[.]").Replace("*", ".*").Replace("?", "."));
            return mask.IsMatch(filename);
        }

        /// <summary>
        /// Deletes files that match the specified pattern regardless of what folder they are in
        /// </summary>
        /// <param name="pattern">The pattern to match (e.g. *.*)</param>
        public virtual void Delete(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                throw new ArgumentException("Pattern must be specified.");


            List<ZipArchiveEntry> toDelete = new List<ZipArchiveEntry>();
            foreach (var entry in _archive.Entries)
            {
                if (FilePatternMatch(entry.FullName, pattern))
                    toDelete.Add(entry);
            }
            if (toDelete.Count > 0)
            {
                _hasChanges = true;
                toDelete.ForEach(x => x.Delete());
            }
        }

        /// <summary>
        /// Finds files that match the specified pattern regardless of what folder they are in
        /// </summary>
        /// <param name="pattern">The pattern to match (e.g. *.*)</param>
        /// <returns>Filenames and paths that match the pattern</returns>
        public IEnumerable<string> FindFiles(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                pattern = "*";
            List<string> files = new List<string>();
            foreach (var entry in _archive.Entries)
            {
                if (FilePatternMatch(entry.FullName, pattern))
                    files.Add(entry.FullName);
            }
            return files;
        }

        /// <summary>
        /// Reads a file from the APK as bytes
        /// </summary>
        /// <param name="targetPath">The full path and filename</param>
        /// <returns>The comtent of the file as bytes</returns>
        public byte[] Read(string targetPath)
        {
            var entry = GetEntry(targetPath);
            if (entry == null)
                throw new FileNotFoundException();

            byte[] bytes = new byte[entry.Length];
            using (var stream = entry.Open())
                stream.Read(bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// Copies a file into the archive without compression
        /// </summary>
        public virtual void CopyFileInto(string sourceFilePath, string destEntryPath)
        {
            _hasChanges = true;
            // this is used for pre-compressed things like songs so no compression is best
            ZipArchiveEntry entry = _archive.CreateEntry(destEntryPath, CompressionLevel.NoCompression);
            using (Stream destStream = entry.Open())
            {
                using (Stream fileStream = new FileStream(sourceFilePath, FileMode.Open))
                {
                    fileStream.CopyTo(destStream);
                }
            }
        }

        #region Signature
        public void Sign()
        {
            if (_readOnly)
                throw new InvalidOperationException("APK is open in read-only mode.");

            //flip the archive into readonly mode
            _archive.Dispose();
            _archive = ZipFile.OpenRead(_filename);

            MemoryStream msManifestFile = new MemoryStream();
            MemoryStream msSigFile = new MemoryStream();

            MemoryStream msSignatureFileBody = new MemoryStream();

            try
            {
                //create the MF file header
                using (StreamWriter swManifest = GetSW(msManifestFile))
                {
                    swManifest.WriteLine("Manifest-Version: 1.0");
                    swManifest.WriteLine("Created-By: emulamer");
                    swManifest.WriteLine();
                }

                //so that we can do it in one pass, write the MF and SF line items at the same time to their respective streams
                foreach (var ze in _archive.Entries.Where(x => !x.FullName.StartsWith("META-INF")))
                {
                    WriteEntryHashes(ze, msManifestFile, msSignatureFileBody);
                }

                //compute the hash on the entirety of the manifest file for the SF file
                msManifestFile.Seek(0, SeekOrigin.Begin);
                var manifestFileHash = _sha.ComputeHash(msManifestFile);



                //write the SF to memory then copy it out to the actual file- contents will be needed later to use for signing, don't want to hit the zip stream twice

                byte[] sigFileBytes = null;

                using (StreamWriter swSignatureFile = GetSW(msSigFile))
                {
                    swSignatureFile.WriteLine("Signature-Version: 1.0");
                    swSignatureFile.WriteLine($"SHA1-Digest-Manifest: {Convert.ToBase64String(manifestFileHash)}");
                    swSignatureFile.WriteLine("Created-By: emulamer");
                    swSignatureFile.WriteLine();
                }
                msSignatureFileBody.Seek(0, SeekOrigin.Begin);
                msSignatureFileBody.CopyTo(msSigFile);
                msSigFile.Seek(0, SeekOrigin.Begin);
                sigFileBytes = msSigFile.ToArray();


                //get the key block (all the hassle distilled into one line), then write it out to the RSA file
                byte[] keyBlock = SignIt(sigFileBytes);

                //flip the archive back into update mode so we can write
                _archive.Dispose();
                _archive = ZipFile.Open(_filename, ZipArchiveMode.Update);

                _hasChanges = true;
                //delete all the META-INF stuff that exists already
                var toDelete = _archive.Entries.Where(x => x.FullName.StartsWith("META-INF")).ToList();
                if (toDelete.Count > 0)
                {
                    toDelete.ForEach(x =>
                    {
                        x.Delete();
                    });
                }

                //write the 3 files                
                msManifestFile.Seek(0, SeekOrigin.Begin);

                var manifestEntry = _archive.CreateEntry("META-INF/MANIFEST.MF");
                using (Stream s = manifestEntry.Open())
                {
                    msManifestFile.CopyTo(s);
                }

                var signaturesEntry = _archive.CreateEntry("META-INF/BS.SF");
                using (Stream s = signaturesEntry.Open())
                {
                    msSigFile.CopyTo(s);
                }

                var rsaEntry = _archive.CreateEntry("META-INF/BS.RSA");
                using (Stream blockStream = rsaEntry.Open())
                {
                    blockStream.Write(keyBlock, 0, keyBlock.Length);
                }

            }
            finally
            {
                if (msManifestFile != null)
                    msManifestFile.Dispose();
                if (msSignatureFileBody != null)
                    msSignatureFileBody.Dispose();
                if (msManifestFile != null)
                    msManifestFile.Dispose();
                if (msSigFile != null)
                    msSigFile.Dispose();
            }


        }

        /// <summary>
        /// Writes the MANIFEST.MF name and hash and the sigfile.SF hash for the sourceFile
        /// </summary>
        private void WriteEntryHashes(ZipArchiveEntry sourceFile, Stream manifestFileStream, Stream signatureFileStream)
        {

            using (Stream s = sourceFile.Open())
            {
                var hash = _sha.ComputeHash(s);
                using (MemoryStream msSection = new MemoryStream())
                {
                    string hashOfMFSection = null;
                    using (StreamWriter swSection = GetSW(msSection))
                    {
                        swSection.WriteLine($"Name: {sourceFile.FullName}");
                        swSection.WriteLine($"SHA1-Digest: {Convert.ToBase64String(hash)}");
                        swSection.WriteLine("");

                    }
                    msSection.Seek(0, SeekOrigin.Begin);
                    hashOfMFSection = Convert.ToBase64String(_sha.ComputeHash(msSection));
                    msSection.Seek(0, SeekOrigin.Begin);
                    var actualString = UTF8Encoding.UTF8.GetString(msSection.ToArray());
                    using (var swSFFile = GetSW(signatureFileStream))
                    {
                        swSFFile.WriteLine($"Name: {sourceFile.FullName}");
                        swSFFile.WriteLine($"SHA1-Digest: {hashOfMFSection}");
                        swSFFile.WriteLine();
                    }

                    msSection.Seek(0, SeekOrigin.Begin);
                    msSection.CopyTo(manifestFileStream);
                }
            }
        }

        /// <summary>
        /// Creates a new X509 certificate and returns its data in PEM format
        /// </summary>
        public string GenerateNewCertificatePEM()
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm("SHA256WithRSA");
            var subjectDN = new X509Name("cn=Unknown");
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date.AddYears(-10));
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(50));
            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            X509Certificate cert = certificateGenerator.Generate(subjectKeyPair.Private);

            using (var writer = new StringWriter())
            {
                var pemWriter = new OpenSsl.PemWriter(writer);

                pemWriter.WriteObject(new PemObject("CERTIFICATE", cert.GetEncoded()));
                pemWriter.WriteObject(subjectKeyPair.Private);
                return writer.ToString();
            }
        }

        private static X509Certificate LoadCert(string pemData, out AsymmetricKeyParameter privateKey)
        {
            X509Certificate cert = null;
            privateKey = null;
            using (var reader = new StringReader(pemData))
            {
                var pemReader = new OpenSsl.PemReader(reader);
                object pemObject = null;
                while ((pemObject = pemReader.ReadObject()) != null)
                {
                    if (pemObject is X509Certificate)
                    {
                        cert = pemObject as X509Certificate;
                    }
                    else if (pemObject is AsymmetricCipherKeyPair)
                    {
                        privateKey = (pemObject as AsymmetricCipherKeyPair).Private;
                    }
                }
            }
            if (cert == null)
                throw new System.Security.SecurityException("Certificate could not be loaded from PEM data.");

            if (privateKey == null)
                throw new System.Security.SecurityException("Private Key could not be loaded from PEM data.");

            return cert;
        }
        /// <summary>
        /// Get a signature block that java will load a JAR with
        /// </summary>
        /// <param name="sfFileData">The data to sign</param>
        /// <returns>The signature block (including certificate) for the data passed in</returns>
        private byte[] SignIt(byte[] sfFileData)
        {
            AsymmetricKeyParameter privateKey = null;

            var cert = LoadCert(_pemData, out privateKey);

            //create things needed to make the CmsSignedDataGenerator work
            var certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(new List<X509Certificate>() { cert }));
            CmsSignedDataGenerator dataGen = new CmsSignedDataGenerator();
            dataGen.AddCertificates(certStore);
            dataGen.AddSigner(privateKey, cert, CmsSignedDataGenerator.EncryptionRsa, CmsSignedDataGenerator.DigestSha256);

            //content is detached- i.e. not included in the signature block itself
            CmsProcessableByteArray detachedContent = new CmsProcessableByteArray(sfFileData);
            var signedContent = dataGen.Generate(detachedContent, false);

            //do lots of stuff to get things in the proper ASN.1 structure for java to parse it properly.  much trial and error.
            var signerInfos = signedContent.GetSignerInfos();
            var signer = signerInfos.GetSigners().Cast<SignerInformation>().First();
            SignerInfo signerInfo = signer.ToSignerInfo();
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"), DerNull.Instance));
            ContentInfo encapContentInfo = new ContentInfo(new DerObjectIdentifier("1.2.840.113549.1.7.1"), null);
            Asn1EncodableVector asnVector = new Asn1EncodableVector();
            asnVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));
            Asn1EncodableVector signersVector = new Asn1EncodableVector();
            signersVector.Add(signerInfo.ToAsn1Object());
            SignedData signedData = new SignedData(new DerSet(digestAlgorithmsVector), encapContentInfo, new BerSet(asnVector), null, new DerSet(signersVector));
            ContentInfo contentInfo = new ContentInfo(new DerObjectIdentifier("1.2.840.113549.1.7.2"), signedData);
            return contentInfo.GetDerEncoded();
        }

        private StreamWriter GetSW(Stream stream)
        {
            return new StreamWriter(stream, _encoding, 1024, true);
        }

        /// <summary>
        /// Gets the file size of a specific file
        /// </summary>
        public Int64 GetFileSize(string filename)
        {
            var entry = GetEntry(filename);
            if (entry == null)
                throw new FileNotFoundException();
            return entry.CompressedLength;
        }

        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_sign && _hasChanges && !_readOnly)
                        Sign();
                    if (_archive != null)
                    {
                        _archive.Dispose();
                        _archive = null;
                    }
                }
                disposedValue = true;
            }
        }



        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
