using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpCompress.Archives.Tar;
using FatumCore;
using AbsolutionLib.Unraveler;

namespace AbsolutionLib.Unraveler.Interfaces
{
    public class TARArchiveInterface : UniCanInterface
    {
        TarArchive TARArchive;
        TarArchiveEntry TARArchiveEntry;

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
        Tree Config;

        int EntryIndex = 0;

        public void SetConfig(Tree config)
        {
            Config = config;
        }

        public Boolean Open(Stream RawStream)
        {
            EntryIndex = 0;
            isClosed = true;

            TARArchive = TarArchive.Open(RawStream);
            isMonoFile = false;
            isClosed = false;

            return true;
        }

        public void extractArchiveEntry()
        {
            if (TARArchiveEntry != null)
            {
                //CurrentFilename = TARArchiveEntry.FilePath;
                CurrentFileLength = TARArchiveEntry.Size;
                CurrentCreatedTime = TARArchiveEntry.CreatedTime.ToString();
                CurrentArchivedTime = TARArchiveEntry.ArchivedTime.ToString();
                CurrentLastModifiedTime = TARArchiveEntry.LastModifiedTime.ToString();
                CurrentLastAccessedTime = TARArchiveEntry.LastAccessedTime.ToString();
                CurrentIsDirectory = TARArchiveEntry.IsDirectory;
                CurrentIsEncrypted = TARArchiveEntry.IsEncrypted;
                CurrentIsComplete = TARArchiveEntry.IsComplete;
                CurrentIsSplit = TARArchiveEntry.IsSplitAfter;
            }
        }

        public DateTime getCreatedDate()
        {
            return (DateTime)TARArchiveEntry.CreatedTime;
        }

        public void Close()
        {
            if (TARArchive != null)
            {
                TARArchive.Dispose();
                TARArchive = null;
            }
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();
            for (int i = 0; i < TARArchive.Entries.Count; i++)
            {

                    TarArchiveEntry current = TARArchive.Entries.ElementAt(i);
                if (current.IsDirectory == false)
                {
                    Tree newFile = new Tree();
                    newFile.addElement("Length", current.Size.ToString());
                    //string filename = Path.GetFileName(current.FilePath);
                    //string directory = Path.GetDirectoryName(current.FilePath);
                    //newFile.addElement("Filename", filename);
                    //newFile.addElement("Directory", directory + "\\");
                    //newFile.addElement("Extension", CanTools.getExtension(filename));
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
            if (TARArchive!=null)
            {
                if (TARArchive.Entries!=null)
                {

                        while (loop)
                        {
                            result = -1;

                            if (EntryIndex < TARArchive.Entries.Count)
                            {
                                TARArchiveEntry = TARArchive.Entries.ElementAt(EntryIndex);
                                if (!TARArchiveEntry.IsDirectory) loop = false;
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
            return TARArchiveEntry.OpenEntryStream();
        }

        public Tree getDetails()
        {
            Tree result = new Tree();
            result.addElement("Length", TARArchiveEntry.Size.ToString());
            result.addElement("Creation", TARArchiveEntry.CreatedTime.ToString());
            result.addElement("Accessed", TARArchiveEntry.LastAccessedTime.ToString());
            result.addElement("Modified", TARArchiveEntry.LastModifiedTime.ToString());
            result.addElement("Archived", TARArchiveEntry.ArchivedTime.ToString());
            if (TARArchiveEntry.IsEncrypted == true)
            {
                result.addElement("Encrypted", TARArchiveEntry.IsEncrypted.ToString().ToLower());
            }
            if (TARArchiveEntry.IsSplitAfter == true)
            {
                result.addElement("Split", TARArchiveEntry.IsSplitAfter.ToString().ToLower());
            }

            return result;
        }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return (DateTime)TARArchiveEntry.LastModifiedTime;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "TAR";
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
            return TARArchiveEntry.Size;
        }
    }
}
