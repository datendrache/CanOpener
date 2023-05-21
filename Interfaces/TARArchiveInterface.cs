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

using SharpCompress.Archives.Tar;
using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
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
                    newFile.AddElement("Length", current.Size.ToString());
                    //string filename = Path.GetFileName(current.FilePath);
                    //string directory = Path.GetDirectoryName(current.FilePath);
                    //newFile.AddElement("Filename", filename);
                    //newFile.AddElement("Directory", directory + "\\");
                    //newFile.AddElement("Extension", CanTools.getExtension(filename));
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
            result.AddElement("Length", TARArchiveEntry.Size.ToString());
            result.AddElement("Creation", TARArchiveEntry.CreatedTime.ToString());
            result.AddElement("Accessed", TARArchiveEntry.LastAccessedTime.ToString());
            result.AddElement("Modified", TARArchiveEntry.LastModifiedTime.ToString());
            result.AddElement("Archived", TARArchiveEntry.ArchivedTime.ToString());
            if (TARArchiveEntry.IsEncrypted == true)
            {
                result.AddElement("Encrypted", TARArchiveEntry.IsEncrypted.ToString().ToLower());
            }
            if (TARArchiveEntry.IsSplitAfter == true)
            {
                result.AddElement("Split", TARArchiveEntry.IsSplitAfter.ToString().ToLower());
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
