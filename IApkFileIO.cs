using System;
using System.Collections.Generic;
using System.IO;

namespace Emulamer.Utils
{
    public interface IApkFileIO : IDisposable
    {
        bool HasChanges { get; }
        bool IsReadOnly { get; }

        void CopyFileInto(string sourceFilePath, string destEntryPath);
        void Delete(string pattern);
        void Dispose();
        bool FileExists(string targetPath);
        IEnumerable<string> FindFiles(string pattern);
        string GenerateNewCertificatePEM();
        long GetFileSize(string filename);
        Stream GetWriteStream(string targetPath, bool overwrite = false, bool compress = true);
        void LoadCert(byte[] certData);
        byte[] Read(string targetPath);
        void Sign();
        void Write(Stream fileData, string targetPath, bool overwrite = false, bool compress = true);
        void Write(string inputFileName, string targetPath, bool overwrite = false, bool compress = true);
    }
}