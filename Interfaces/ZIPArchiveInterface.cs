using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpCompress;
using SharpCompress.Archives.Zip;
using FatumCore;
using AbsolutionLib.Unraveler;

namespace AbsolutionLib.Unraveler.Interfaces
{
    public class ZIPArchiveInterface : UniCanInterface
    {
        ZipArchive ZIPArchive;
        ZipArchiveEntry ZIPArchiveEntry;
        Tree Config = null;

        string FileName;

        public string CurrentFilename = "";
        public long CurrentFileLength = 0;
        public String CurrentCreatedTime;
        public String CurrentArchivedTime;
        public String CurrentLastModifiedTime;
        public String CurrentLastAccessedTime;
        public Boolean CurrentIsDirectory;
        public Boolean CurrentIsEncrypted;
        public Boolean CurrentIsComplete;
        public Boolean CurrentIsSplit;

        public Boolean isMonoFile = false;
        public Boolean isClosed = true;

        BinaryReader FileStream;
        public Stream CurrentEntryStream;

        int EntryIndex = 0;

        public void SetConfig(Tree config)
        {
            Config = config;
        }

        public Boolean Open(Stream RawStream)
        {
            EntryIndex = 0;
            isClosed = true;


                ZIPArchive = ZipArchive.Open(RawStream);
                isMonoFile = false;
                isClosed = false;


            return true;
        }

        public void extractArchiveEntry()
        {
            if (ZIPArchiveEntry!=null)
            {
                CurrentFileLength = ZIPArchiveEntry.Size;
                CurrentCreatedTime = ZIPArchiveEntry.CreatedTime.ToString();
                CurrentArchivedTime = ZIPArchiveEntry.ArchivedTime.ToString();
                CurrentLastModifiedTime = ZIPArchiveEntry.LastModifiedTime.ToString();
                CurrentLastAccessedTime = ZIPArchiveEntry.LastAccessedTime.ToString();
                CurrentIsDirectory = ZIPArchiveEntry.IsDirectory;
                CurrentIsEncrypted = ZIPArchiveEntry.IsEncrypted;
                CurrentIsComplete = ZIPArchiveEntry.IsComplete;
                CurrentIsSplit = ZIPArchiveEntry.IsSplitAfter;
            }
        }

        public DateTime getCreatedDate()
        {
            return (DateTime)ZIPArchiveEntry.CreatedTime;
        }

        public void Close()
        {
            if (ZIPArchive != null)
            {
                ZIPArchive.Dispose();
                ZIPArchive = null;
            }
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();

            for (int i = 0; i < ZIPArchive.Entries.Count; i++)
            {

                ZipArchiveEntry current = ZIPArchive.Entries.ElementAt(i);
                if (current.IsDirectory == false)
                {
                    Tree newFile = new Tree();
                    newFile.addElement("Length", current.Size.ToString());
                    newFile.addElement("Creation", current.CreatedTime.ToString());
                    newFile.addElement("Accessed", current.LastAccessedTime.ToString());
                    newFile.addElement("Modified", current.LastModifiedTime.ToString());
                    newFile.addElement("Archived", current.ArchivedTime.ToString());
                    newFile.addElement("Encrypted", current.IsEncrypted.ToString());
                    newFile.addElement("Split", current.IsSplitAfter.ToString());
                    result.addNode(newFile, "File");

                }
            }
            return result;
        }

        public int nextEntry()
            {
                int result = -1;
                Boolean loop = true;
                if (ZIPArchive != null)
                {
                    if (ZIPArchive.Entries != null)
                    {
                        while (loop)
                        {
                            result = -1;

                            if (EntryIndex < ZIPArchive.Entries.Count)
                            {
                                ZIPArchiveEntry = ZIPArchive.Entries.ElementAt(EntryIndex);
                                if (!ZIPArchiveEntry.IsDirectory) loop = false;
                                result = EntryIndex;
                            }

                            if (result == -1)
                            {
                                loop = false;
                            }
                            else
                            {
                                extractEntryData();
                                if (loop) EntryIndex++;
                            }
                        }
                    }
                }


                if (result > -1)
                {
                    extractEntryData();
                    EntryIndex++;
                }
                return result;
            }

        public Stream OpenCurrentEntry()
        {
            return ZIPArchiveEntry.OpenEntryStream();
        }

        public Tree getDetails()
            {
                Tree result = new Tree();
                result.addElement("Length", ZIPArchiveEntry.Size.ToString());
                result.addElement("Creation", ZIPArchiveEntry.CreatedTime.ToString());
                result.addElement("Accessed", ZIPArchiveEntry.LastAccessedTime.ToString());
                result.addElement("Modified", ZIPArchiveEntry.LastModifiedTime.ToString());
                result.addElement("Archived", ZIPArchiveEntry.ArchivedTime.ToString());
                if (ZIPArchiveEntry.IsEncrypted == true)
                {
                    result.addElement("Encrypted", ZIPArchiveEntry.IsEncrypted.ToString().ToLower());
                }
                if (ZIPArchiveEntry.IsSplitAfter == true)
                {
                    result.addElement("Split", ZIPArchiveEntry.IsSplitAfter.ToString().ToLower());
                }
                return result;
            }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return (DateTime)ZIPArchiveEntry.LastModifiedTime;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "ZIP";
        }

        public void CloseCurrentEntry()
        {
            CurrentEntryStream.Close();
        }
        public Boolean IsClosed()
        {
            return isClosed;
        }

        public long GetFileLength()
        {
            return ZIPArchiveEntry.Size;
        }
    }
}
