using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FatumCore;
using AbsolutionLib.Unraveler;

namespace AbsolutionLib.Unraveler.Interfaces
{
    public class FileArchiveInterface : UniCanInterface
    {
        BinaryReader FileStream;

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

        public Stream CurrentEntryStream;

        public Tree Config = null;

        public void SetConfig(Tree config)
        {
            Config = config;
        }

        public Boolean Open(Stream RawStream)
        {
            Boolean result = false;

            if (!isClosed)
            {
                Close();
            }

            if (FileName.Contains("|"))
            {
                isClosed = true;
                return false;
            }
            else
            {
                if (!FileName.Contains(":"))
                {
                    return false;
                }
                else
                {
                    try
                    {
                        RawStream = File.OpenRead(FileName);
                    }
                    catch (Exception xyz)
                    {
                        return false;
                    }
                }
            }

                FileStream = new BinaryReader(RawStream);
                isMonoFile = true;
                result = true;


            isClosed = false;

            return result;
        }

        public void extractArchiveEntry()
        {

        }

        public DateTime getCreatedDate()
        {
            return DateTime.MinValue;
        }

        public void Close()
        {
            if (FileStream != null) FileStream.Close();
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();
            Tree newFile = new Tree();
            newFile.addElement("Filename", "");
            newFile.addElement("Directory", "\\");
            newFile.addElement("UnknownArchiveFormat", "true");
            result.addNode(newFile, "FILE");
            return result;
        }

        public int nextEntry()
        {
            return -1;
        }

        public Stream OpenCurrentEntry()
        {
            return null;
        }

        public Tree getDetails()
        {
            Tree result = new Tree();
            Tree newFile = new Tree();
            newFile.addElement("Filename", "");
            newFile.addElement("Directory", "\\");
            newFile.addElement("UnknownArchiveFormat", "true");
            result.addNode(newFile, "FILE");
            return result;
        }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return DateTime.MinValue;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "Unknown";
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
            return 0;
        }
    }
}
