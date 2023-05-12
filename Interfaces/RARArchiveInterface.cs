using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpCompress.Archives.Rar;
using FatumCore;
using AbsolutionLib.Unraveler;

namespace AbsolutionLib.Unraveler.Interfaces
{
    public class RARArchiveInterface : UniCanInterface
    {
        RarArchive RARArchive;
        RarArchiveEntry RARArchiveEntry;

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
        Tree Config = null;

        public void SetConfig(Tree config)
        {
            Config = config;
        }

        public Boolean Open(Stream RawStream)
        {
            EntryIndex = 0;
            isClosed = true;

                RARArchive = RarArchive.Open(RawStream);
                isMonoFile = false;
                isClosed = false;

            return true;
        }

        public void extractArchiveEntry()
        {
            if (RARArchiveEntry != null)
            {
                //CurrentFilename = RARArchiveEntry.FileName;
                CurrentFileLength = RARArchiveEntry.Size;
                CurrentCreatedTime = RARArchiveEntry.CreatedTime.ToString();
                CurrentArchivedTime = RARArchiveEntry.ArchivedTime.ToString();
                CurrentLastModifiedTime = RARArchiveEntry.LastModifiedTime.ToString();
                CurrentLastAccessedTime = RARArchiveEntry.LastAccessedTime.ToString();
                CurrentIsDirectory = RARArchiveEntry.IsDirectory;
                CurrentIsEncrypted = RARArchiveEntry.IsEncrypted;
                CurrentIsComplete = RARArchiveEntry.IsComplete;
                //CurrentIsSplit = RARArchiveEntry.IsSplit;
            }
        }

        public DateTime getCreatedDate()
        {
            return (DateTime)RARArchiveEntry.CreatedTime;
        }

        public void Close()
        {
            if (RARArchive != null)
            {
                RARArchive.Dispose();
                RARArchive = null;
            }
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();
            try
            {
                string Directory = "";

                foreach (RarArchiveEntry current in RARArchive.Entries)
                {
                    if (current.IsDirectory == false)
                    {
                        Tree newFile = new Tree();
                        newFile.addElement("Length", current.Size.ToString());
                        string filename = Path.GetFileName(current.Key);
                        string directory = Directory;
                        newFile.addElement("Filename", filename);
                        newFile.addElement("Directory", directory + "\\");
                        newFile.addElement("Extension", CanTools.getExtension(filename));
                        newFile.addElement("Creation", current.CreatedTime.ToString());
                        newFile.addElement("Accessed", current.LastAccessedTime.ToString());
                        newFile.addElement("Modified", current.LastModifiedTime.ToString());
                        newFile.addElement("Archived", current.ArchivedTime.ToString());
                        newFile.addElement("Encrypted", current.IsEncrypted.ToString());
                        newFile.addElement("Split", current.IsSplitAfter.ToString());
                        result.addNode(newFile, "File");
                    }
                    else
                    {
                        Directory = current.Key;
                    }
                }
            }
            catch (Exception)
            {

            }
            return result;
        }

        public int nextEntry()
        {
            int result = -1;
            Boolean loop = true;

            if (RARArchive!=null)
            {
                if (RARArchive.Entries!=null)
                {

                        while (loop)
                        {
                            result = -1;

                            if (EntryIndex < RARArchive.Entries.Count)
                            {
                                RARArchiveEntry = RARArchive.Entries.ElementAt(EntryIndex);
                                if (!RARArchiveEntry.IsDirectory) loop = false;
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
            return RARArchiveEntry.OpenEntryStream();
        }

        public Tree getDetails()
        {
            Tree result = new Tree();
            result.addElement("Length", RARArchiveEntry.Size.ToString());
            result.addElement("Creation", RARArchiveEntry.CreatedTime.ToString());
            result.addElement("Accessed", RARArchiveEntry.LastAccessedTime.ToString());
            result.addElement("Modified", RARArchiveEntry.LastModifiedTime.ToString());
            result.addElement("Archived", RARArchiveEntry.ArchivedTime.ToString());
            if (RARArchiveEntry.IsEncrypted == true)
            {
                result.addElement("Encrypted", RARArchiveEntry.IsEncrypted.ToString().ToLower());
            }
            if (RARArchiveEntry.IsSplitAfter == true)
            {
                result.addElement("Split", RARArchiveEntry.IsSplitAfter.ToString().ToLower());
            }

            return result;
        }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return (DateTime)RARArchiveEntry.LastModifiedTime;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "RAR";
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
            return RARArchiveEntry.Size;
        }
    }
}
