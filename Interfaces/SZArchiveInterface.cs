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

using SharpCompress.Archives.SevenZip;
using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
{
    public class SZArchiveInterface : UniCanInterface
    {
        SevenZipArchive SZArchive;
        SevenZipArchiveEntry SZArchiveEntry;

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

                SZArchive = SevenZipArchive.Open(RawStream);
                isMonoFile = false;
                isClosed = false;

            return true;
        }

        public void extractArchiveEntry()
        {
            if (SZArchiveEntry!=null)
            {
                CurrentFileLength = SZArchiveEntry.Size;
                CurrentIsDirectory = SZArchiveEntry.IsDirectory;
                CurrentIsEncrypted = SZArchiveEntry.IsEncrypted;
                CurrentIsComplete = SZArchiveEntry.IsComplete;
                CurrentIsSplit = SZArchiveEntry.IsSplitAfter;
            }
        }

        public DateTime getCreatedDate()
        {
            return (DateTime)SZArchiveEntry.CreatedTime;
        }

        public void Close()
        {
            if (SZArchive != null)
            {
                SZArchive.Dispose();
                SZArchive = null;
            }
            isClosed = true;
        }

        public Tree getAllArchiveContent()
        {
            Tree result = new Tree();
            for (int i = 0; i < SZArchive.Entries.Count; i++)
            {
                SevenZipArchiveEntry current = SZArchive.Entries.ElementAt(i);
                if (current.IsDirectory == false)
                {
                    Tree newFile = new Tree();
                    newFile.AddElement("Length", current.Size.ToString());
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

            if (SZArchive!=null)
            {
                if (SZArchive.Entries!=null)
                {
                        while (loop)
                        {
                            result = -1;

                            if (EntryIndex < SZArchive.Entries.Count)
                            {
                                SZArchiveEntry = SZArchive.Entries.ElementAt(EntryIndex);
                                if (!SZArchiveEntry.IsDirectory) loop = false;
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
            return SZArchiveEntry.OpenEntryStream();
        }

        public Tree getDetails()
        {
            Tree result = new Tree();
            result.AddElement("Length", SZArchiveEntry.Size.ToString());
            result.AddElement("Creation", SZArchiveEntry.CreatedTime.ToString());
            result.AddElement("Accessed", SZArchiveEntry.LastAccessedTime.ToString());
            result.AddElement("Modified", SZArchiveEntry.LastModifiedTime.ToString());
            result.AddElement("Archived", SZArchiveEntry.ArchivedTime.ToString());
            if (SZArchiveEntry.IsEncrypted == true)
            {
                result.AddElement("Encrypted", SZArchiveEntry.IsEncrypted.ToString().ToLower());
            }
            if (SZArchiveEntry.IsSplitAfter == true)
            {
                result.AddElement("Split", SZArchiveEntry.IsSplitAfter.ToString().ToLower());
            }

            return result;
        }

        public void extractEntryData()
        {
            extractArchiveEntry();
        }

        public DateTime getLastModifiedDate()
        {
            return (DateTime)SZArchiveEntry.LastModifiedTime;
        }

        public Tree getAllFileInfo()
        {
            return getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return "7Z";
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
            return SZArchiveEntry.Size;
        }
    }
}
