//   CanOpener -- A library for identifying and recursively opening archives
//
//   Copyright (C) 2003-2023 Eric Knight
//   This software is distributed under the GNU Public v3 License
//
//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.

//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <https://www.gnu.org/licenses/>.

using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
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
            newFile.AddElement("Filename", "");
            newFile.AddElement("Directory", "\\");
            newFile.AddElement("UnknownArchiveFormat", "true");
            result.AddNode(newFile, "FILE");
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
            newFile.AddElement("Filename", "");
            newFile.AddElement("Directory", "\\");
            newFile.AddElement("UnknownArchiveFormat", "true");
            result.AddNode(newFile, "FILE");
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
