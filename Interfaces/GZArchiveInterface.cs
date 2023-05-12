using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpCompress.Archives.GZip;
using FatumCore;
using AbsolutionLib.Unraveler;

namespace AbsolutionLib.Unraveler.Interfaces
{
    public class GZArchiveInterface : UniCanInterface
    {
        GZipArchive GZArchive;
        GZipArchiveEntry GZArchiveEntry;

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
        Tree Config = null;

        int EntryIndex = 0;

        public void SetConfig(Tree config)
        {
            Config = config;
        }

        public Boolean Open(Stream RawStream)
        {
            EntryIndex = 0;
            isClosed = true;

                GZArchive = GZipArchive.Open(RawStream); 
                isMonoFile = false;
                isClosed = false;


            return true;
        }

        public void extractArchiveEntry()
        {
            //CurrentFilename = GZArchiveEntry.FilePath;
            CurrentFileLength = GZArchiveEntry.Size;
            CurrentCreatedTime = GZArchiveEntry.CreatedTime.ToString();
            CurrentArchivedTime = GZArchiveEntry.ArchivedTime.ToString();
            CurrentLastModifiedTime = GZArchiveEntry.LastModifiedTime.ToString();
            CurrentLastAccessedTime = GZArchiveEntry.LastAccessedTime.ToString();
            CurrentIsDirectory = GZArchiveEntry.IsDirectory;
            CurrentIsEncrypted = GZArchiveEntry.IsEncrypted;
            CurrentIsComplete = GZArchiveEntry.IsComplete;
            CurrentIsSplit = GZArchiveEntry.IsSplitAfter;
        }

        public DateTime getCreatedDate()
        {
            return (DateTime)GZArchiveEntry.CreatedTime;
        }

        public void Close()
        {
            if (GZArchive != null)
            {
                GZArchive.Dispose();
                GZArchive = null;
            }
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();
            for (int i = 0; i < GZArchive.Entries.Count; i++)
            {
                GZipArchiveEntry current = GZArchive.Entries.ElementAt(i);
                if (current.IsDirectory == false)
                {
                    Tree newFile = new Tree();
                    newFile.addElement("Length", current.Size.ToString());
                    string filename = "GZData";
                    //string directory = Path.GetDirectoryName(current.FilePath);
                    newFile.addElement("Filename", filename);
                    newFile.addElement("Directory", "\\");
                    newFile.addElement("Extension", CanTools.getExtension(filename));
                    newFile.addElement("Creation", current.CreatedTime.ToString());
                    newFile.addElement("Accessed", current.LastAccessedTime.ToString());
                    newFile.addElement("Modified", current.LastModifiedTime.ToString());
                    newFile.addElement("Archived", current.ArchivedTime.ToString());
                    newFile.addElement("Encrypted", current.IsEncrypted.ToString());
                    newFile.addElement("Split", current.IsSplitAfter.ToString());
                    result.addNode(newFile, "FILE");
                }
            }
            return result;
        }
        
        public int nextEntry()
        {
            int result = -1;
            Boolean loop = true;
            if (GZArchive!=null)
            {
                if (GZArchive.Entries!=null)
                {

                        while (loop)
                        {
                            result = -1;

                            if (EntryIndex < GZArchive.Entries.Count)
                            {
                                GZArchiveEntry = GZArchive.Entries.ElementAt(EntryIndex);
                                if (!GZArchiveEntry.IsDirectory) loop = false;
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
            return GZArchiveEntry.OpenEntryStream();
        }

        public Tree getDetails()
        {
            Tree result = new Tree();
            result.addElement("Length", GZArchiveEntry.Size.ToString());

                result.addElement("Creation", GZArchiveEntry.CreatedTime.ToString());
                result.addElement("Accessed", GZArchiveEntry.LastAccessedTime.ToString());
                result.addElement("Modified", GZArchiveEntry.LastModifiedTime.ToString());
                result.addElement("Archived", GZArchiveEntry.ArchivedTime.ToString());
                if (GZArchiveEntry.IsEncrypted == true)
                {
                    result.addElement("Encrypted", GZArchiveEntry.IsEncrypted.ToString().ToLower());
                }
                if (GZArchiveEntry.IsSplitAfter == true)
                {
                    result.addElement("Split", GZArchiveEntry.IsSplitAfter.ToString().ToLower());
                }

            return result;
        }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return (DateTime)GZArchiveEntry.LastModifiedTime;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "GZ";
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
            return GZArchiveEntry.Size;
        }
    }
}
