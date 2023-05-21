﻿//   CanOpener -- A library for identifying and recursively opening archives
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

using SharpCompress.Archives.GZip;
using Proliferation.Fatum;

namespace Proliferation.CanOpener.Interfaces
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
                    newFile.AddElement("Length", current.Size.ToString());
                    string filename = "GZData";
                    //string directory = Path.GetDirectoryName(current.FilePath);
                    newFile.AddElement("Filename", filename);
                    newFile.AddElement("Directory", "\\");
                    newFile.AddElement("Extension", CanTools.getExtension(filename));
                    newFile.AddElement("Creation", current.CreatedTime.ToString());
                    newFile.AddElement("Accessed", current.LastAccessedTime.ToString());
                    newFile.AddElement("Modified", current.LastModifiedTime.ToString());
                    newFile.AddElement("Archived", current.ArchivedTime.ToString());
                    newFile.AddElement("Encrypted", current.IsEncrypted.ToString());
                    newFile.AddElement("Split", current.IsSplitAfter.ToString());
                    result.AddNode(newFile, "FILE");
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
            result.AddElement("Length", GZArchiveEntry.Size.ToString());

                result.AddElement("Creation", GZArchiveEntry.CreatedTime.ToString());
                result.AddElement("Accessed", GZArchiveEntry.LastAccessedTime.ToString());
                result.AddElement("Modified", GZArchiveEntry.LastModifiedTime.ToString());
                result.AddElement("Archived", GZArchiveEntry.ArchivedTime.ToString());
                if (GZArchiveEntry.IsEncrypted == true)
                {
                    result.AddElement("Encrypted", GZArchiveEntry.IsEncrypted.ToString().ToLower());
                }
                if (GZArchiveEntry.IsSplitAfter == true)
                {
                    result.AddElement("Split", GZArchiveEntry.IsSplitAfter.ToString().ToLower());
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
