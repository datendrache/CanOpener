using System;
using System.IO;
using FatumCore;

namespace AbsolutionLib.Unraveler.Interfaces
{
    interface UniCanInterface
    {
        Boolean Open(Stream RawStream);
        void Close();
        void extractArchiveEntry();
        DateTime getCreatedDate();
        Tree getAllArchiveContent();
        int nextEntry();
        Stream OpenCurrentEntry();
        Tree getDetails();
        void SetConfig(Tree Config);
        void extractEntryData();
        DateTime getLastModifiedDate();
        Tree getAllFileInfo();
        string getArchiveName();
        void CloseCurrentEntry();
        Boolean IsClosed();
        long GetFileLength();

    }
}
