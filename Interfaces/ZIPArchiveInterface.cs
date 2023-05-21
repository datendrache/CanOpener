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

using SharpCompress.Archives.Zip;
using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
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
                    newFile.AddElement("Length", current.Size.ToString());
                    newFile.AddElement("Creation", current.CreatedTime.ToString());
                    newFile.AddElement("Accessed", current.LastAccessedTime.ToString());
                    newFile.AddElement("Modified", current.LastModifiedTime.ToString());
                    newFile.AddElement("Archived", current.ArchivedTime.ToString());
                    newFile.AddElement("Encrypted", current.IsEncrypted.ToString());
                    newFile.AddElement("Split", current.IsSplitAfter.ToString());
                    result.AddNode(newFile, "File");

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
                result.AddElement("Length", ZIPArchiveEntry.Size.ToString());
                result.AddElement("Creation", ZIPArchiveEntry.CreatedTime.ToString());
                result.AddElement("Accessed", ZIPArchiveEntry.LastAccessedTime.ToString());
                result.AddElement("Modified", ZIPArchiveEntry.LastModifiedTime.ToString());
                result.AddElement("Archived", ZIPArchiveEntry.ArchivedTime.ToString());
                if (ZIPArchiveEntry.IsEncrypted == true)
                {
                    result.AddElement("Encrypted", ZIPArchiveEntry.IsEncrypted.ToString().ToLower());
                }
                if (ZIPArchiveEntry.IsSplitAfter == true)
                {
                    result.AddElement("Split", ZIPArchiveEntry.IsSplitAfter.ToString().ToLower());
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
