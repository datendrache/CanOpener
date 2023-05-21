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

using SharpCompress.Archives.Rar;
using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
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
                        newFile.AddElement("Length", current.Size.ToString());
                        string filename = Path.GetFileName(current.Key);
                        string directory = Directory;
                        newFile.AddElement("Filename", filename);
                        newFile.AddElement("Directory", directory + "\\");
                        newFile.AddElement("Extension", CanTools.getExtension(filename));
                        newFile.AddElement("Creation", current.CreatedTime.ToString());
                        newFile.AddElement("Accessed", current.LastAccessedTime.ToString());
                        newFile.AddElement("Modified", current.LastModifiedTime.ToString());
                        newFile.AddElement("Archived", current.ArchivedTime.ToString());
                        newFile.AddElement("Encrypted", current.IsEncrypted.ToString());
                        newFile.AddElement("Split", current.IsSplitAfter.ToString());
                        result.AddNode(newFile, "File");
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
            result.AddElement("Length", RARArchiveEntry.Size.ToString());
            result.AddElement("Creation", RARArchiveEntry.CreatedTime.ToString());
            result.AddElement("Accessed", RARArchiveEntry.LastAccessedTime.ToString());
            result.AddElement("Modified", RARArchiveEntry.LastModifiedTime.ToString());
            result.AddElement("Archived", RARArchiveEntry.ArchivedTime.ToString());
            if (RARArchiveEntry.IsEncrypted == true)
            {
                result.AddElement("Encrypted", RARArchiveEntry.IsEncrypted.ToString().ToLower());
            }
            if (RARArchiveEntry.IsSplitAfter == true)
            {
                result.AddElement("Split", RARArchiveEntry.IsSplitAfter.ToString().ToLower());
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
