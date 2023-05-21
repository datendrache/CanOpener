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

namespace Proliferation.CanOpener
{
    public class FileID
    {
        public static long identifiedFiles = 0;
        public static long symboliclinks = 0;

        public FileID()
        {
            //
            // TODO: Add Constructor Logic here
            //
        }

        private static string removeSlashes(string stringwithtoomanyslashes)
        {
            string result = stringwithtoomanyslashes;

            Boolean loop = true;
            while (loop)
            {
                if (result.Contains("\\\\"))
                {
                    result = result.Replace("\\\\", "\\");
                }
                else
                {
                    loop = false;
                }
            }
            return result;
        }

        public static Tree Identify(string filename, byte[] Chunk, int ChunkSize, Boolean keepCount)
        {
            Tree newFileInformation = new Tree();
            Boolean Evaluate = true;
            FileInfo newInfo = new FileInfo(filename);

            string Extension = newInfo.Extension;
            Extension = Extension.ToUpper();

            if (Extension == null) Extension = "<none>";

            string FileLength = newInfo.Length.ToString();
            string Filename = newInfo.Name;
            string Directory = newInfo.DirectoryName;
            string Creation = newInfo.CreationTime.ToUniversalTime().ToString();
            string Accessed = newInfo.LastAccessTime.ToUniversalTime().ToString();
            string Modified = newInfo.LastWriteTime.ToUniversalTime().ToString();

            newFileInformation.SetElement("Length", FileLength);
            newFileInformation.SetElement("Extension", Extension);
            newFileInformation.SetElement("Filename", Filename);
            newFileInformation.SetElement("Directory", removeSlashes(Directory) + "\\");
            newFileInformation.SetElement("Creation", Creation);
            newFileInformation.SetElement("Accessed", Accessed);
            newFileInformation.SetElement("Modified", Modified);

            FileAttributes f = newInfo.Attributes;

            if ((f & FileAttributes.Archive) == FileAttributes.Archive)
                newFileInformation.SetElement("ArchiveCandidate", "true");
            if ((f & FileAttributes.Compressed) == FileAttributes.Compressed)
            {
                newFileInformation.SetElement("Compressed", "true");
                //newFileInformation.SetElement("Search","false");
            }
            if ((f & FileAttributes.Device) == FileAttributes.Device)
                newFileInformation.SetElement("Device", "true");
            if ((f & FileAttributes.Directory) == FileAttributes.Directory)
            {
                newFileInformation.SetElement("Search", "false");
                newFileInformation.SetElement("Directory", "true");
                Evaluate = false;
            }
            if ((f & FileAttributes.Encrypted) == FileAttributes.Encrypted)
            {
                newFileInformation.SetElement("Search", "false");
                newFileInformation.SetElement("Encrypted", "true");
            }
            if ((f & FileAttributes.Hidden) == FileAttributes.Hidden)
                newFileInformation.SetElement("Hidden", "true");
            if ((f & FileAttributes.NotContentIndexed) == FileAttributes.NotContentIndexed)
                newFileInformation.SetElement("NotContentIndexed", "true");
            if ((f & FileAttributes.Offline) == FileAttributes.Offline)
            {
                newFileInformation.SetElement("Offline", "true");
                newFileInformation.SetElement("Search", "false");
                Evaluate = false;
            }
            if ((f & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                newFileInformation.SetElement("ReadOnly", "true");
            if ((f & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                newFileInformation.SetElement("ReparsePoint", "true");
                newFileInformation.SetElement("Search", "false");
            }
            if ((f & FileAttributes.SparseFile) == FileAttributes.SparseFile)
                newFileInformation.SetElement("SparseFile", "true");
            if ((f & FileAttributes.System) == FileAttributes.System)
                newFileInformation.SetElement("System", "true");
            if ((f & FileAttributes.Temporary) == FileAttributes.Temporary)
                newFileInformation.SetElement("Temporary", "true");

            if (Evaluate)
            {
                identifyChunk(newFileInformation, Chunk, ChunkSize, keepCount);
            }

            string chunktype = newFileInformation.GetElement("Type");
            if (chunktype != null)
            {
                switch (chunktype)
                {
                    case "Windows Link":
                    case "REGISTRYHIVE":
                    case "REGTRANS-MS":
                        newFileInformation.SetElement("Search", "false");
                        break;
                }
            }
            return (newFileInformation);
        }

        public static Tree identifyExtension(string Extension)
        {
            Tree ExtensionInfo = new Tree();

            return (ExtensionInfo);
        }

        public static void identifyChunk(Tree CFI, byte[] Chunk, int ChunkSize, Boolean keepCount)
        {
            Boolean Executable = false;
            Boolean found = false;
            Boolean TextHTML = false;
            Boolean Identified = false;

            if (ChunkSize == 0)
            {
                CFI.SetElement("Empty", "true");
                CFI.SetElement("Executable", "false");
                CFI.SetElement("Text", "false");
            }
            else
            {
                Boolean asciicheck = true;
                for (int i = 0; i < ChunkSize; i++)
                {
                    byte CurrentChar = Chunk[i];
                    if (CurrentChar > 128)
                    {
                            asciicheck = false;
                            i = ChunkSize;
                    }
                    else
                    {
                        if (CurrentChar < 32)
                        {
                            if (CurrentChar != 10 || CurrentChar != 13)
                            {
                                asciicheck = false;
                                i = ChunkSize;
                            }
                        }
                    }
                }

                // EXECUTABLE FILE FORMATS

                //  Identify a Windows EXE file 4D 5A

                if (ChunkSize > 1 && !found)
                {
                    if (Chunk[0] == 0x4D)
                    {
                        if (Chunk[1] == 0x5A)
                        {
                            Executable = true;
                            CFI.SetElement("Confirm", ".EXE");
                            CFI.SetElement("Type", "Executable");
                            CFI.AddElement("Details", "Microsoft PE/COFF Executable");
                            Identified=true; found=true;
                        }
                    }
                }

                //  Identify a Unix Binary ELF file 7f 45 4c 46

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x7F)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x4C)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    Executable = true;
                                    CFI.SetElement("Confirm", "Unix ELF");
                                    CFI.SetElement("Type", "Executable");
                                    CFI.AddElement("Details", "Linux/Posix ELF Format");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Unix ar or Microsoft Library 21 3c 61 72 63 68 3e 0a

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x21)
                    {
                        if (Chunk[1] == 0x3c)
                        {
                            if (Chunk[2] == 0x61)
                            {
                                if (Chunk[3] == 0x72)
                                {
                                    if (Chunk[4] == 0x63)
                                    {
                                        if (Chunk[5] == 0x68)
                                        {
                                            if (Chunk[6] == 0x3e)
                                            {
                                                if (Chunk[7] == 0x0a)
                                                {
                                                    Executable = true;
                                                    CFI.SetElement("Confirm", ".LIB");
                                                    CFI.SetElement("Type", "Executable");
                                                    CFI.AddElement("Details", "C/C++ Library");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a Java Class CA FE BA BE

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0xCA)
                    {
                        if (Chunk[1] == 0xFE)
                        {
                            if (Chunk[2] == 0xBA)
                            {
                                if (Chunk[3] == 0xBE)
                                {
                                    Executable = true;
                                    CFI.SetElement("Confirm", ".CLASS");
                                    CFI.SetElement("Type", "Executable");
                                    CFI.AddElement("Details", "Sun Microsystems JAVA class object");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Shockwave Flash file v5+ 43 57 53

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x57)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                Executable = true;
                                CFI.SetElement("Confirm", ".CWS");
                                CFI.SetElement("Type", "Executable");
                                CFI.AddElement("Details", "Adobe Shockwave v5+");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                //  InstallShield v5 or v6 Compressed File 49 53 63 28

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x63)
                            {
                                if (Chunk[3] == 0x28)
                                {
                                    Executable = true;
                                    CFI.SetElement("Confirm", ".CAB");
                                    CFI.SetElement("Type", "Executable");
                                    CFI.AddElement("Details", "Microsoft InstallShield v5-6 Compressed Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Shockwave Flash file v5+ 43 57 53

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4c)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            Executable = true;
                            CFI.SetElement("Confirm", ".OBJ");
                            CFI.SetElement("Type", "Executable");
                            CFI.AddElement("Details", "Adobe Shockwave v5+");
                            Identified=true; found = true;
                        }
                    }
                }

                //  OLE SPSS or Visual C++ Library File 4D 53 46 54 02 00 01 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x46)
                            {
                                if (Chunk[3] == 0x54)
                                {
                                    if (Chunk[4] == 0x02)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x01)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    Executable = true;
                                                    CFI.SetElement("Confirm", ".TLB");
                                                    CFI.SetElement("Type", "Executable");
                                                    CFI.AddElement("Details", "OLE SPSS or Visual C++ Library");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Adobe Plugin Executables 4D 5A 90 00 03 00 00 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x5a)
                        {
                            if (Chunk[2] == 0x90)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x03)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    Executable = true;
                                                    CFI.SetElement("Confirm", ".API");
                                                    CFI.SetElement("Type", "Executable");
                                                    CFI.AddElement("Details", "Adobe Plugin Executable");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Windows/DOS Executable

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x5a)
                        {
                            Executable = true;
                            CFI.SetElement("Confirm", ".OBJ");
                            CFI.SetElement("Type", "Executable");
                            CFI.AddElement("Details", "Windows or DOS Executable");
                            Identified=true; found = true;
                        }
                    }
                }

                // Microsoft C++ debugging symbols file  4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x69)
                        {
                            if (Chunk[2] == 0x63)
                            {
                                if (Chunk[3] == 0x72)
                                {
                                    if (Chunk[4] == 0x6f)
                                    {
                                        if (Chunk[5] == 0x73)
                                        {
                                            if (Chunk[6] == 0x6f)
                                            {
                                                if (Chunk[7] == 0x66)
                                                {
                                                    if (Chunk[8] == 0x74)
                                                    {
                                                        if (Chunk[9] == 0x20)
                                                        {
                                                            if (Chunk[10] == 0x43)
                                                            {
                                                                if (Chunk[11] == 0x2f)
                                                                {
                                                                    if (Chunk[12] == 0x43)
                                                                    {
                                                                        if (Chunk[13] == 0x2b)
                                                                        {
                                                                            if (Chunk[14] == 0x2b)
                                                                            {
                                                                                if (Chunk[15] == 0x20)
                                                                                {
                                                                                    Executable = true;
                                                                                    CFI.SetElement("Confirm", ".PDB");
                                                                                    CFI.SetElement("Type", "Executable");
                                                                                    CFI.AddElement("Details", "Microsoft C++ Debugging Symbols File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Antenna Data File 52 45 56 4E 55 4D 3A 2C 

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x56)
                            {
                                if (Chunk[3] == 0x4e)
                                {
                                    if (Chunk[4] == 0x55)
                                    {
                                        if (Chunk[5] == 0x4d)
                                        {
                                            if (Chunk[6] == 0x3a)
                                            {
                                                if (Chunk[7] == 0x2c)
                                                {
                                                    Executable = true;
                                                    CFI.SetElement("Confirm", ".ADF");
                                                    CFI.SetElement("Type", "Executable");
                                                    CFI.AddElement("Details", "Antenna Executable File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Dalvilk Executable File 64 65 78 0A 30 30 39 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x64)
                    {
                        if (Chunk[1] == 0x65)
                        {
                            if (Chunk[2] == 0x78)
                            {
                                if (Chunk[3] == 0x0a)
                                {
                                    if (Chunk[4] == 0x30)
                                    {
                                        if (Chunk[5] == 0x30)
                                        {
                                            if (Chunk[6] == 0x39)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    CFI.SetElement("Confirm", ".DEX");
                                                    CFI.SetElement("Type", "Executable");
                                                    CFI.AddElement("Details", "Dalvilk Executable File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


// DOCUMENT FILE FORMATS

                //  Identify a Microsoft DOC file D0 CF 11 E0

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0xD0)
                    {
                        if (Chunk[1] == 0xCF)
                        {
                            if (Chunk[2] == 0x11)
                            {
                                if (Chunk[3] == 0xE0)
                                {
                                    CFI.SetElement("Confirm", ".DOC");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Word Document");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Identify a Perfect Writer Type 4 file offset 640 - 06 54 59 50 45 20 34

                if (ChunkSize > 647 && !found)
                {
                    if (Chunk[640] == 0x06)
                    {
                        if (Chunk[641] == 0x54)
                        {
                            if (Chunk[642] == 0x59)
                            {
                                if (Chunk[643] == 0x50)
                                {
                                    if (Chunk[644] == 0x45)
                                    {
                                        if (Chunk[645] == 0x20)
                                        {
                                            if (Chunk[646] == 0x34)
                                            {
                                                CFI.SetElement("Confirm", ".PW4");
                                                CFI.SetElement("Type", "Document");
                                                CFI.AddElement("Details", "Perfect Writer Type 4 Document");
                                                Identified = true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a Perfect Writer Type 2 file offset 15 - 06 54 59 50 45 32 30

                if (ChunkSize > 24 && !found)
                {
                    if (Chunk[15] == 0x06)
                    {
                        if (Chunk[16] == 0x54)
                        {
                            if (Chunk[17] == 0x59)
                            {
                                if (Chunk[18] == 0x50)
                                {
                                    if (Chunk[19] == 0x45)
                                    {
                                        if (Chunk[20] == 0x32)
                                        {
                                            if (Chunk[21] == 0x30)
                                            {
                                                CFI.SetElement("Confirm", ".PW2");
                                                CFI.SetElement("Type", "Document");
                                                CFI.AddElement("Details", "Perfect Writer Type 2 Document");
                                                Identified = true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify Unknown EP300 file format offset 0 - 2a 0c 45 50 33 30 30

                if (ChunkSize > 24 && !found)
                {
                    if (Chunk[0] == 0x2a)
                    {
                        if (Chunk[1] == 0x0c)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x50)
                                {
                                    if (Chunk[4] == 0x33)
                                    {
                                        if (Chunk[5] == 0x30)
                                        {
                                            if (Chunk[6] == 0x30)
                                            {

                                                CFI.SetElement("Confirm", ".EPD");
                                                CFI.SetElement("Type", "Document");
                                                CFI.AddElement("Details", "Unknown Business EP300 Document");
                                                Identified = true; found = true;

                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify Unknown PAGES file format offset 0 - 00 04 50 41 47 45 53

                if (ChunkSize > 24 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x04)
                        {
                            if (Chunk[2] == 0x50)
                            {
                                if (Chunk[3] == 0x41)
                                {
                                    if (Chunk[4] == 0x47)
                                    {
                                        if (Chunk[5] == 0x45)
                                        {
                                            if (Chunk[6] == 0x53)
                                            {

                                                CFI.SetElement("Confirm", ".EPT");
                                                CFI.SetElement("Type", "Document");
                                                CFI.AddElement("Details", "Unknown Business EP300-Pages Document");
                                                Identified = true; found = true;

                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Adobe Encapsulated PostScript File 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 20 30

                if (ChunkSize > 70 && !found)
                {
                    for (int i=0;i<40;i++)
                    {
                        if (Chunk[0 + i] == 0x25)
                        {
                            if (Chunk[1 + i] == 0x21)
                            {
                                if (Chunk[2 + i] == 0x50)
                                {
                                    if (Chunk[3 + i] == 0x53)
                                    {
                                        if (Chunk[4 + i] == 0x2d)
                                        {
                                            if (Chunk[5 + i] == 0x41)
                                            {
                                                if (Chunk[6 + i] == 0x64)
                                                {
                                                    if (Chunk[7 + i] == 0x6f)
                                                    {
                                                        if (Chunk[8 + i] == 0x62)
                                                        {
                                                            if (Chunk[9 + i] == 0x65)
                                                            {
                                                                if (Chunk[10 + i] == 0x2d)
                                                                {
                                                                    if (Chunk[11 + i] == 0x33)
                                                                    {
                                                                        if (Chunk[12 + i] == 0x2e)
                                                                        {
                                                                            if (Chunk[13 + i] == 0x30)
                                                                            {
                                                                                if (Chunk[14 + i] == 0x20)
                                                                                {
                                                                                    if (Chunk[15 + i] == 0x45)
                                                                                    {
                                                                                        if (Chunk[16 + i] == 0x50)
                                                                                        {
                                                                                            if (Chunk[17 + i] == 0x53)
                                                                                            {
                                                                                                if (Chunk[18 + i] == 0x46)
                                                                                                {
                                                                                                    if (Chunk[19 + i] == 0x2d)
                                                                                                    {
                                                                                                        if (Chunk[20 + i] == 0x33)
                                                                                                        {
                                                                                                            if (Chunk[21 + i] == 0x20)
                                                                                                            {
                                                                                                                if (Chunk[22 + i] == 0x30)
                                                                                                                {
                                                                                                                    CFI.SetElement("Confirm", ".EPS");
                                                                                                                    CFI.SetElement("Type", "Document");
                                                                                                                    CFI.AddElement("Details", "Adobe Encapsulated PostScript File");
                                                                                                                    Identified=true; found = true;
                                                                                                                    i = 40;
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  WKS Deskmate Worksheet 0e 57 4b 53

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x0E)
                    {
                        if (Chunk[1] == 0x57)
                        {
                            if (Chunk[2] == 0x4B)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    CFI.SetElement("Confirm", ".WKS");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "WKS Deskmate Worksheet");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Windows 9x printer spool file 4B 49 00 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4b)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".SHD");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows 9x Printer Spool File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                // Microsoft Money File 00 01 00 00 4d 53 49 53 41 4d 20 44 61 74 61 62 61 73 65

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x4d)
                                    {
                                        if (Chunk[5] == 0x53)
                                        {
                                            if (Chunk[6] == 0x49)
                                            {
                                                if (Chunk[7] == 0x53)
                                                {
                                                    if (Chunk[8] == 0x41)
                                                    {
                                                        if (Chunk[9] == 0x4d)
                                                        {
                                                            if (Chunk[10] == 0x20)
                                                            {
                                                                if (Chunk[11] == 0x44)
                                                                {
                                                                    if (Chunk[12] == 0x61)
                                                                    {
                                                                        if (Chunk[13] == 0x74)
                                                                        {
                                                                            if (Chunk[14] == 0x61)
                                                                            {
                                                                                if (Chunk[15] == 0x62)
                                                                                {
                                                                                    if (Chunk[16] == 0x61)
                                                                                    {
                                                                                        if (Chunk[17] == 0x73)
                                                                                        {
                                                                                            if (Chunk[18] == 0x65)
                                                                                            {
                                                                                                CFI.SetElement("Confirm", ".MNY");
                                                                                                CFI.SetElement("Type", "Document");
                                                                                                CFI.AddElement("Details", "Microsoft Money File");
                                                                                                Identified=true; found=true;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a Microsoft BMP file 42 4d  (MOVED FROM IMAGES - SOMETIMES CONFLICTS WITH Adobe PDF)

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x42)
                    {
                        if (Chunk[1] == 0x4D)
                        {
                            CFI.SetElement("Confirm", ".BMP");
                            CFI.SetElement("Type", "Picture");
                            CFI.AddElement("Details", "Microsoft Bitmap");
                            Identified=true; found = true;
                        }
                    }
                }

                //  Identify an Adobe PDF file 25 50 44 46

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x25)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x44)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".PDF");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Adobe Portable Document Format");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Identify a PostScript file 25 21

                if (ChunkSize > 1 && !found)
                {
                    if (Chunk[0] == 0x42)
                    {
                        if (Chunk[1] == 0x4D)
                        {
                            CFI.SetElement("Confirm", ".PS");
                            CFI.SetElement("Type", "Document");
                            CFI.AddElement("Details", "PostScript Document");
                            Identified=true; found=true;
                        }
                    }
                }

                //  Identify Lotus 1-2-3 v1 file 00 00 02 00 06 04 06 00 08 00 00 00 00 00

                if (ChunkSize > 14 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x02)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x06)
                                        {
                                            if (Chunk[5] == 0x04)
                                            {
                                                if (Chunk[6] == 0x06)
                                                {
                                                    if (Chunk[7] == 0x00)
                                                    {
                                                        if (Chunk[8] == 0x08)
                                                        {
                                                            if (Chunk[9] == 0x0A)
                                                            {
                                                                if (Chunk[10] == 0x00)
                                                                {
                                                                    if (Chunk[11] == 0x00)
                                                                    {
                                                                        if (Chunk[12] == 0x00)
                                                                        {
                                                                            if (Chunk[13] == 0x00)
                                                                            {
                                                                                if (Chunk[14] == 0x00)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".WK1");
                                                                                    CFI.SetElement("Type", "Document");
                                                                                    CFI.AddElement("Details", "IBM Lotus 1-2-3 Workbook File v1");
                                                                                    Identified=true; found=true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                // Lotus 1-2-3 Spreadsheet v3 00 00 1a 00 00 10 04 00 00 00 00 00

                if (ChunkSize > 12 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x1a)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x00)
                                        {
                                            if (Chunk[5] == 0x10)
                                            {
                                                if (Chunk[6] == 0x04)
                                                {
                                                    if (Chunk[7] == 0x00)
                                                    {
                                                        if (Chunk[8] == 0x00)
                                                        {
                                                            if (Chunk[9] == 0x00)
                                                            {
                                                                if (Chunk[10] == 0x00)
                                                                {
                                                                    if (Chunk[11] == 0x00)
                                                                    {
                                                                        CFI.SetElement("Confirm", ".WK3");
                                                                        CFI.SetElement("Type", "Document");
                                                                        CFI.AddElement("Details", "IBM Lotus 1-2-3 Workbook File v3");
                                                                        Identified=true; found=true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Lotus 1-2-3 Spreadsheet v5 00 00 1a 00 20 10 40 00

                if (ChunkSize > 8 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x1a)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x20)
                                        {
                                            if (Chunk[5] == 0x10)
                                            {
                                                if (Chunk[6] == 0x40)
                                                {
                                                    if (Chunk[7] == 0x00)
                                                    {
                                                        CFI.SetElement("Confirm", ".WK5");
                                                        CFI.SetElement("Type", "Document");
                                                        CFI.AddElement("Details", "IBM Lotus 1-2-3 Workbook File v5");
                                                        Identified=true; found=true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                // Quicken QuickFinder Information File 50 00 00 00 20 00 00 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x20)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    CFI.SetElement("Confirm", ".IDX");
                                                    CFI.SetElement("Type", "Document");
                                                    CFI.AddElement("Details", "Quicken QuickFinder Information File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                    // Lotus 1-2-3 Spreadsheet v9 00 00 1a 00 50 10 04

                if (ChunkSize > 7 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x1a)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x50)
                                        {
                                            if (Chunk[5] == 0x10)
                                            {
                                                if (Chunk[6] == 0x04)
                                                {
                                                        CFI.SetElement("Confirm", ".WK9");
                                                        CFI.SetElement("Type", "Document");
                                                        CFI.AddElement("Details", "IBM Lotus 1-2-3 Workbook File v9");
                                                        Identified=true; found=true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Quark Express document 00 00 49|4D 49|4D 58 50 52

                if (ChunkSize > 7 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x49 | Chunk[2] == 0x4D)
                                {
                                    if (Chunk[3] == 0x49 | Chunk[3] == 0x4D)
                                    {
                                        if (Chunk[4] == 0x58)
                                        {
                                            if (Chunk[5] == 0x50)
                                            {
                                                if (Chunk[6] == 0x52)
                                                {
                                                    CFI.SetElement("Confirm", ".QXD");
                                                    CFI.SetElement("Type", "Document");
                                                    CFI.AddElement("Details", "Quark Express Document");
                                                    Identified=true; found=true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                //  DOC Deskmate Document File 0D 44 4F 43

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x0D)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x4F)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    CFI.SetElement("Confirm", ".DDOC");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Deskmate Document File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  wordStar Version 5/6

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1D)
                    {
                        if (Chunk[1] == 0x7D)
                        {
                            CFI.SetElement("Confirm", ".WS");
                            CFI.SetElement("Type", "Document");
                            CFI.AddElement("Details", "WordStar Document");
                            Identified=true; found = true;
                        }
                    }
                }

                //  Microsoft Write File 31 BE or 32 BE

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x31 | Chunk[0] == 32)
                    {
                        if (Chunk[1] == 0xBE)
                        {
                            CFI.SetElement("Confirm", ".WRI");
                            CFI.SetElement("Type", "Document");
                            CFI.AddElement("Details", "Microsoft Write File");
                            Identified=true; found = true;
                        }
                    }
                }

                //  Quattro Pro for Windows 7.0 Notebook File 3E 00 03 00 FE FF 09 00 06

                if (ChunkSize > 34 && !found)
                {
                    if (Chunk[24] == 0x3e)
                    {
                        if (Chunk[25] == 0x00)
                        {
                            if (Chunk[26] == 0x03)
                            {
                                if (Chunk[27] == 0x00)
                                {
                                    if (Chunk[28] == 0xfe)
                                    {
                                        if (Chunk[29] == 0xff)
                                        {
                                            if (Chunk[30] == 0x09)
                                            {
                                                if (Chunk[31] == 0x00)
                                                {
                                                    if (Chunk[32] == 0x06)
                                                    {
                                                        CFI.SetElement("Confirm", ".WB3");
                                                        CFI.SetElement("Type", "Document");
                                                        CFI.AddElement("Details", "Quattro Pro Notebook File");
                                                        Identified=true; found = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Windows Help file or index file  3F 5F 03 00

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x3f)
                    {
                        if (Chunk[1] == 0x5f)
                        {
                            if (Chunk[2] == 0x03)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".HLP");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows Help or Index File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Windows Help file or index file  4C 4E 02 00

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4c)
                    {
                        if (Chunk[1] == 0x4e)
                        {
                            if (Chunk[2] == 0x02)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".HLP");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows Help or Index File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Compiled Windows Help file or index file  49 54 53 46

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x54)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".CHI");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows Compiled Help or Index File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicken Data File + 51 45 4C 20 + 92 byte offset 

                if (ChunkSize > 96 && !found)
                {
                    if (Chunk[92] == 0x51)
                    {
                        if (Chunk[93] == 0x45)
                        {
                            if (Chunk[94] == 0x4c)
                            {
                                if (Chunk[95] == 0x20)
                                {
                                    CFI.SetElement("Confirm", ".QEL");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Quicken Data File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  EndNote Library File  40 40 40 20 00 00 40 40 40 40  + 32 bytes offset

                if (ChunkSize > 42 && !found)
                {
                    if (Chunk[32] == 0x40)
                    {
                        if (Chunk[33] == 0x40)
                        {
                            if (Chunk[34] == 0x40)
                            {
                                if (Chunk[35] == 0x20)
                                {
                                    if (Chunk[36] == 0x00)
                                    {
                                        if (Chunk[37] == 0x00)
                                        {
                                            if (Chunk[38] == 0x40)
                                            {
                                                if (Chunk[39] == 0x40)
                                                {
                                                    if (Chunk[40] == 0x40)
                                                    {
                                                        if (Chunk[41] == 0x40)
                                                        {
                                                            CFI.SetElement("Confirm", ".ENL");
                                                            CFI.SetElement("Type", "Document");
                                                            CFI.AddElement("Details", "Endnote Library File");
                                                            Identified=true; found = true;
                                                        }
                                                    }
                                                }
                                            }
                    
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // RagTime Document File 43 23 2B 44 A4 43 4D A5 48 64 72

                if (ChunkSize > 11 && !found)
                    {
                        if (Chunk[0] == 0x43)
                        {
                            if (Chunk[1] == 0x23)
                            {
                                if (Chunk[2] == 0x2b)
                                {
                                    if (Chunk[3] == 0x44)
                                    {
                                        if (Chunk[4] == 0xa4)
                                        {
                                            if (Chunk[5] == 0x43)
                                            {
                                                if (Chunk[6] == 0x4d)
                                                {
                                                    if (Chunk[7] == 0xa5)
                                                    {
                                                        if (Chunk[8] == 0x48)
                                                        {
                                                            if (Chunk[9] == 0x64)
                                                            {
                                                                if (Chunk[10] == 0x72)
                                                                {
                                                                    CFI.SetElement("Confirm", ".RTD");
                                                                    CFI.SetElement("Type", "Document");
                                                                    CFI.AddElement("Details", "RagTime Document");
                                                                    Identified=true; found = true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                // Intuit QuickBooks Backup File 45 86 00 00 06 00

                if (ChunkSize > 7 && !found)
                {
                    if (Chunk[0] == 0x45)
                    {
                        if (Chunk[1] == 0x86)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x06)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            CFI.SetElement("Confirm", ".QXD");
                                            CFI.SetElement("Type", "Document");
                                            CFI.AddElement("Details", "Intuit QuickBooks Backup File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Microsoft FAX Cover Sheet  46 41 58 43 4F 56 45 52 2D 56 45 52

                if (ChunkSize > 12 && !found)
                {
                    if (Chunk[0] == 0x46)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x58)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    if (Chunk[4] == 0x4f)
                                    {
                                        if (Chunk[5] == 0x56)
                                        {
                                            if (Chunk[6] == 0x45)
                                            {
                                                if (Chunk[7] == 0x52)
                                                {
                                                    if (Chunk[8] == 0x2d)
                                                    {
                                                        if (Chunk[9] == 0x56)
                                                        {
                                                            if (Chunk[10] == 0x45)
                                                            {
                                                                if (Chunk[11] == 0x52)
                                                                {
                                                                    CFI.SetElement("Confirm", ".CPE");
                                                                    CFI.SetElement("Type", "Document");
                                                                    CFI.AddElement("Details", "Microsoft FAX Cover Sheet");
                                                                    Identified=true; found = true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Harvard Graphics Presentation File 48 48 47 42 31

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x48)
                    {
                        if (Chunk[1] == 0x48)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x42)
                                {
                                    if (Chunk[3] == 0x31)
                                    {
                                        CFI.SetElement("Confirm", ".SH3");
                                        CFI.SetElement("Type", "Document");
                                        CFI.AddElement("Details", "Harvard Graphics Presentation File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // Microsoft Reader eBook file 49 54 4F 4C 49 54 4C 53

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x54)
                        {
                            if (Chunk[2] == 0x4f)
                            {
                                if (Chunk[3] == 0x4c)
                                {
                                    if (Chunk[4] == 0x49)
                                    {
                                        if (Chunk[5] == 0x54)
                                        {
                                            if (Chunk[6] == 0x4c)
                                            {
                                                if (Chunk[7] == 0x53)
                                                {
                                                    CFI.SetElement("Confirm", ".LIT");
                                                    CFI.SetElement("Type", "Document");
                                                    CFI.AddElement("Details", "Microsoft Reader eBook File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

//  ARCHIVE FILE FORMATS

                //  Identify a ZIP file 50 4B 03 04 14 00 01 00 63 00 00 00 00 00

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x4B)
                        {
                            if (Chunk[2] == 0x03)
                            {
                                if (Chunk[3] == 0x04)
                                {
                                    if (Chunk[4] == 0x14)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x01)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    if (Chunk[8] == 0x63)
                                                    {
                                                        if (Chunk[9] == 0x00)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                if (Chunk[11] == 0x00)
                                                                {
                                                                    if (Chunk[12] == 0x00)
                                                                    {
                                                                        if (Chunk[13] == 0x00)
                                                                        {
                                                                            CFI.SetElement("Confirm", ".ZIP");
                                                                            CFI.SetElement("Type", "Archive");
                                                                            CFI.AddElement("Details", "ZIP Archive");
                                                                            Identified=true; found = true;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a ZIP file 50 4B 03 04

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x4B)
                        {
                            if (Chunk[2] == 0x03)
                            {
                                if (Chunk[3] == 0x04)
                                {
                                    CFI.SetElement("Confirm", ".ZIP");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "ZIP Archive");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  JAR Archive  5F 27 A8 89

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x5f)
                    {
                        if (Chunk[1] == 0x27)
                        {
                            if (Chunk[2] == 0xa8)
                            {
                                if (Chunk[3] == 0x89)
                                {
                                    CFI.SetElement("Confirm", ".JAR");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "JAR Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  ARJ Archive  60 EA

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x60)
                    {
                        if (Chunk[1] == 0xea)
                        {

                            CFI.SetElement("Confirm", ".ARJ");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "ARJ Archive");
                            Identified=true; found = true;
                        }
                    }
                }

                //  Multivolume ZIP file 50 4B 07 08

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x4B)
                        {
                            if (Chunk[2] == 0x03)
                            {
                                if (Chunk[3] == 0x04)
                                {
                                    CFI.SetElement("Confirm", ".ZIP");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Multivolume ZIP Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Zoo archive 5A 4F 4F 20

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x5a)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4f)
                            {
                                if (Chunk[3] == 0x20)
                                {
                                    CFI.SetElement("Confirm", ".ZOO");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "ZOO Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }


                //  Empty ZIP file 50 4B 05 06

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x4B)
                        {
                            if (Chunk[2] == 0x05)
                            {
                                if (Chunk[3] == 0x06)
                                {
                                    CFI.SetElement("Confirm", ".ZIP");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Empty ZIP Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  FreeArc compressed file 41 72 43 01

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x72)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x01)
                                {
                                    CFI.SetElement("Confirm", ".ARC");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "FreeARC Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a RAR file 52 61 72 21 

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x61)
                        {
                            if (Chunk[2] == 0x72)
                            {
                                if (Chunk[3] == 0x21)
                                {
                                    CFI.SetElement("Confirm", ".RAR");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "RAR Archive");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Microsoft MSN MARC Archive  4D 41 52 43

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    CFI.SetElement("Confirm", ".MAR");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Microsoft MSN MARC Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a GZ file 1F 8B

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1F)
                    {
                        if (Chunk[1] == 0x8B)
                        {
                            CFI.SetElement("Confirm", ".GZ");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "Gnu ZIP Archive");
                            Identified=true; found=true;
                        }
                    }
                }

                //  Identify a Z file 1F 9D

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1F)
                    {
                        if (Chunk[1] == 0x9D)
                        {
                            CFI.SetElement("Confirm", ".Z");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "Z Compress Archive");
                            Identified=true; found=true;
                        }
                    }
                }

                //  Identify a Z file 1F A0

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1F)
                    {
                        if (Chunk[1] == 0xA0)
                        {
                            CFI.SetElement("Confirm", ".Z");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "Z Compress Archive");
                            Identified=true; found = true;
                        }
                    }
                }


                //  Identify a BZ2 file 42 5A 68

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x42)
                    {
                        if (Chunk[1] == 0x5A)
                        {
                            if (Chunk[1] == 0x68)
                            {
                                CFI.SetElement("Confirm", ".BZ2");
                                CFI.SetElement("Type", "Archive");
                                CFI.AddElement("Details", "BZ2 Archive");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                //  Identify a BZ file 42 5A

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x42)
                    {
                        if (Chunk[1] == 0x5A)
                        {
                            CFI.SetElement("Confirm", ".BZ");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "BZ Archive");
                            Identified=true; found=true;
                        }
                    }
                }

                //  7ZIP 37 7A BC AF 27 1C

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x37)
                    {
                        if (Chunk[1] == 0x7a)
                        {
                            if (Chunk[2] == 0xbc)
                            {
                                if (Chunk[3] == 0xaf)
                                {
                                    if (Chunk[4] == 0x27)
                                    {
                                        if (Chunk[5] == 0x1c)
                                        {
                                            CFI.SetElement("Confirm", ".7Z");
                                            CFI.SetElement("Type", "Archive");
                                            CFI.AddElement("Details", "7ZIP Archive");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  CPIO 30 37 30 37 30

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x30)
                    {
                        if (Chunk[1] == 0x37)
                        {
                            if (Chunk[2] == 0x30)
                            {
                                if (Chunk[3] == 0x37)
                                {
                                    if (Chunk[4] == 0x30)
                                    {

                                        CFI.SetElement("Confirm", ".CPIO");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.AddElement("Details", "CPIO Archive");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  MAR Mozilla Archive 4D 41 52 31 00

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x31)
                                {
                                    if (Chunk[4] == 0x00)
                                    {

                                        CFI.SetElement("Confirm", ".MAR");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.AddElement("Details", "Mozilla Archive");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  MAr Compressed Archive 4D 41 72 30 00

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x72)
                            {
                                if (Chunk[3] == 0x30)
                                {
                                    if (Chunk[4] == 0x00)
                                    {

                                        CFI.SetElement("Confirm", ".MAR");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.AddElement("Details", "Mozilla Archive");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  ZISOFS Compression 37 E4 53 96 C9 DB D6 07

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x37)
                    {
                        if (Chunk[1] == 0xe4)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x96)
                                {
                                    if (Chunk[4] == 0xc9)
                                    {
                                        if (Chunk[5] == 0xd6)
                                        {
                                            if (Chunk[6] == 0x07)
                                            {
                                                CFI.SetElement("Confirm", ".ZISOFS");
                                                CFI.SetElement("Type", "Archive");
                                                CFI.AddElement("Details", "ZISOFS Archive");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a POSIX TAR file 75 73 74 61 72

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x75)
                    {
                        if (Chunk[1] == 0x73)
                        {
                            if (Chunk[2] == 0x74)
                            {
                                if (Chunk[3] == 0x61)
                                {
                                    if (Chunk[4] == 0x72)
                                    {
                                        CFI.SetElement("Confirm", ".TAR");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.AddElement("Details", "Tape Archive");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Microsoft CAB Misc 4D 53 43 46

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".CAB");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Microsoft CAB Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify Microsoft Compression Format file 4D 53 43 46

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4D)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".CAB");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Microsoft CAB Archive");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Quake Archive File 50 41 43 4B

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x48)
                                {
                                    CFI.SetElement("Confirm", ".PAK");
                                    CFI.SetElement("Type", "Archive");
                                    CFI.AddElement("Details", "Quake Archive");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  LHA/LZH Compressed Archive File 2d 6c 68 (+2 byte offset)

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[2] == 0x2d)
                    {
                        if (Chunk[3] == 0x6c)
                        {
                            if (Chunk[4] == 0x68)
                            {

                                CFI.SetElement("Confirm", ".LZH");
                                CFI.SetElement("Type", "Archive");
                                CFI.AddElement("Details", "LHA or LZH Archive");
                                Identified=true; found = true;
                            }
                        }
                    }
                }


                //  Blackberry Backup File 49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x6e)
                        {
                            if (Chunk[2] == 0x74)
                            {
                                if (Chunk[3] == 0x65)
                                {
                                    if (Chunk[5] == 0x72)
                                    {
                                        if (Chunk[6] == 0x40)
                                        {
                                            if (Chunk[7] == 0x63)
                                            {
                                                if (Chunk[8] == 0x74)
                                                {
                                                    if (Chunk[9] == 0x69)
                                                    {
                                                        if (Chunk[10] == 0x76)
                                                        {
                                                            if (Chunk[11] == 0x65)
                                                            {
                                                                if (Chunk[12] == 0x20)
                                                                {
                                                                    if (Chunk[13] == 0x50)
                                                                    {
                                                                        if (Chunk[14] == 0x61)
                                                                        {
                                                                            if (Chunk[15] == 0x67)
                                                                            {
                                                                                if (Chunk[16] == 0x65)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".IPD");
                                                                                    CFI.SetElement("Type", "Archive");
                                                                                    Identified=true; found = true;
                                                                                    CFI.AddElement("Details", "Blackberry Archive");
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Binhex 28 54 68 69 73 20 66 69 6C 65 20 6D 75 73 74 20 62 65 20 63 6F 6E 76 65 72 74 65 64 20 77 69 74 68 20 42 69 6E 48 65 78 20

                if (ChunkSize > 20 && !found)
                {
                    if (Chunk[0] == 0x28)
                    {
                        if (Chunk[1] == 0x54)
                        {
                            if (Chunk[2] == 0x68)
                            {
                                if (Chunk[3] == 0x69)
                                {
                                    if (Chunk[4] == 0x73)
                                    {
                                        if (Chunk[5] == 0x20)
                                        {
                                            if (Chunk[6] == 0x66)
                                            {
                                                if (Chunk[7] == 0x69)
                                                {
                                                    if (Chunk[8] == 0x6c)
                                                    {
                                                        if (Chunk[9] == 0x65)
                                                        {
                                                            if (Chunk[10] == 0x20)
                                                            {
                                                                if (Chunk[11] == 0x6d)
                                                                {
                                                                    if (Chunk[12] == 0x75)
                                                                    {
                                                                        if (Chunk[13] == 0x73)
                                                                        {
                                                                            if (Chunk[14] == 0x74)
                                                                            {
                                                                                if (Chunk[15] == 0x20)
                                                                                {
                                                                                    if (Chunk[16] == 0x62)
                                                                                    {
                                                                                        if (Chunk[17] == 0x65)
                                                                                        {
                                                                                            if (Chunk[18] == 0x20)
                                                                                            {
                                                                                                if (Chunk[19] == 0x63)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x6f)  // We cut this short this is a lot of ascii text
                                                                                                    {

                                                                                                        CFI.SetElement("Confirm", ".HQX");
                                                                                                        CFI.SetElement("Type", "Archive");
                                                                                                        CFI.AddElement("Details", "Binhex Archive");
                                                                                                        Identified=true; found = true;
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  CRUSH Compression Format file 43 52 55 53 48 20 76

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x55)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    if (Chunk[4] == 0x48)
                                    {
                                        if (Chunk[5] == 0x20)
                                        {
                                            if (Chunk[6] == 0x76)
                                            {
                                                CFI.SetElement("Confirm", ".CRU");
                                                CFI.SetElement("Type", "Archive");
                                                CFI.AddElement("Details", "CRUSH Archive");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  JARCS compressed archive 4A 41 52 43 53 00

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x4A)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    if (Chunk[4] == 0x53)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            CFI.SetElement("Confirm", ".JAR");
                                            CFI.SetElement("Type", "Archive");
                                            CFI.AddElement("Details", "JAR Archive");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  KGB Archive  4B 47 42 5F 61 72 63 68 20 2D

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x4b)
                    {
                        if (Chunk[1] == 0x47)
                        {
                            if (Chunk[2] == 0x42)
                            {
                                if (Chunk[3] == 0x5f)
                                {
                                    if (Chunk[4] == 0x61)
                                    {
                                        if (Chunk[5] == 0x72)
                                        {
                                            if (Chunk[6] == 0x63)
                                            {
                                                if (Chunk[7] == 0x68)
                                                {
                                                    if (Chunk[8] == 0x20)
                                                    {
                                                        if (Chunk[9] == 0x2d)
                                                        {
                                                            CFI.SetElement("Confirm", ".KGB");
                                                            CFI.SetElement("Type", "Archive");
                                                            CFI.AddElement("Details", "KGB Archive");
                                                            Identified=true; found = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  KWAJ Format (MS-DOS) 4B 57 41 4A 88 F0 27 D1

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x4b)
                    {
                        if (Chunk[1] == 0x57)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0x4a)
                                {
                                    if (Chunk[4] == 0x88)
                                    {
                                        if (Chunk[5] == 0xf0)
                                        {
                                            if (Chunk[6] == 0x27)
                                            {
                                                if (Chunk[7] == 0xd1)
                                                {

                                                    CFI.SetElement("Confirm", ".KWAJ");
                                                    CFI.SetElement("Type", "Archive");
                                                    CFI.AddElement("Details", "KWAJ Archive");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  SZDD Format (MS-DOS) 53 5A 44 44 88 F0 27 33

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x5a)
                        {
                            if (Chunk[2] == 0x44)
                            {
                                if (Chunk[3] == 0x44)
                                {
                                    if (Chunk[4] == 0x88)
                                    {
                                        if (Chunk[5] == 0xf0)
                                        {
                                            if (Chunk[6] == 0x27)
                                            {
                                                if (Chunk[7] == 0x33)
                                                {

                                                    CFI.SetElement("Confirm", ".SZDD");
                                                    CFI.SetElement("Type", "Archive");
                                                    CFI.AddElement("Details", "SZDD Archive");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  StuffIt compressed archive  53 49 54 21 00

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x21)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        CFI.SetElement("Confirm", ".SIT");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.AddElement("Details", "StuffIt Archive");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // StuffIt compressed archive 53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x74)
                        {
                            if (Chunk[2] == 0x75)
                            {
                                if (Chunk[3] == 0x66)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x74)
                                            {
                                                if (Chunk[7] == 0x20)
                                                {

                                                    CFI.SetElement("Confirm", ".SIT");
                                                    CFI.SetElement("Type", "Archive");
                                                    CFI.AddElement("Details", "StuffIt Archive");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // UFA compressed archive 55 46 41 C6 D2 C1

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x55)
                    {
                        if (Chunk[1] == 0x46)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0xc6)
                                {
                                    if (Chunk[4] == 0xd2)
                                    {
                                        if (Chunk[5] == 0xc1)
                                        {

                                            CFI.SetElement("Confirm", ".UFA");
                                            CFI.SetElement("Type", "Archive");
                                            CFI.AddElement("Details", "UFA Archive");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


// ENCRYPTED

                //  Identify a PGP file A8 03 50 47 50 

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0xA8)
                    {
                        if (Chunk[1] == 0x03)
                        {
                            if (Chunk[2] == 0x50)
                            {
                                if (Chunk[3] == 0x47)
                                {
                                    if (Chunk[4] == 0x50)
                                    {
                                        CFI.SetElement("Confirm", ".PGP");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.SetElement("Encrypted", "true");
                                        CFI.AddElement("Details", "Pretty Good Privacy Encrypted Archive");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a ENC Mujajideen Secrets 2 file 00 5c 41 b1 ff

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x5c)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0xb1)
                                {
                                    if (Chunk[4] == 0xff)
                                    {
                                        CFI.SetElement("Confirm", ".ENC");
                                        CFI.SetElement("Type", "Archive");
                                        CFI.SetElement("Encrypted", "true");
                                        CFI.AddElement("Details", "ENC Mujajideen Secrets 2 Encrypted File");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  AES 41 45 53

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x53)
                            {

                                CFI.SetElement("Confirm", ".AES");
                                CFI.SetElement("Type", "Archive");
                                CFI.SetElement("Encrypted", "true");
                                CFI.AddElement("Details", "AES Encrypted Archive");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                //  PAX Password Protected Bitmap 50 41 58

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x58)
                            {
                                CFI.SetElement("Confirm", ".PAX");
                                CFI.SetElement("Type", "Picture");
                                CFI.AddElement("Details", "PAX Password Protected Bitmap");
                                CFI.SetElement("Encrypted", "true");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                // PGP Disk Image   50 47 50 64 4D 41 49 4E

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x47)
                        {
                            if (Chunk[2] == 0x50)
                            {
                                if (Chunk[3] == 0x64)
                                {
                                    if (Chunk[4] == 0x4d)
                                    {
                                        if (Chunk[5] == 0x41)
                                        {
                                            if (Chunk[6] == 0x49)
                                            {
                                                if (Chunk[7] == 0x4e)
                                                {

                                                    CFI.SetElement("Confirm", ".PGD");
                                                    CFI.SetElement("Type", "DriveImage");
                                                    CFI.AddElement("Details", "Pretty Good Privacy Encrypted Disk Image");
                                                    CFI.SetElement("Encrypted", "true");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

//  PICTURE FILE FORMATS

                //  Identify a JPG file FF D8 FF E0

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0xFF)
                    {
                        if (Chunk[1] == 0xD8)
                        {
                            if (Chunk[2] == 0xFF)
                            {
                                if (Chunk[3] == 0xE0)
                                {
                                    CFI.SetElement("Confirm", ".JPG");
                                    CFI.AddElement("Details", "Joint Photographics Experts Group JPG Image");
                                    CFI.SetElement("Type", "Picture");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }

                //  IMG Software Set Bitmap 53 43 48 6c

                    if (ChunkSize > 4 && !found)
                    {
                        if (Chunk[0] == 0x53)
                        {
                            if (Chunk[1] == 0x43)
                            {
                                if (Chunk[2] == 0x48)
                                {
                                    if (Chunk[3] == 0x6c)
                                    {
                                        CFI.SetElement("Confirm", ".JPG");
                                        CFI.SetElement("Type", "Picture");
                                        CFI.AddElement("Details", "IMG Bitmap");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }

                //  Tagged Image File Format (TIFF) 49 20 49

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x20)
                        {
                            if (Chunk[2] == 0x49)
                            {
                                    CFI.SetElement("Confirm", ".TIFF");
                                    CFI.AddElement("Details", "Tagged Image File Format");
                                    CFI.SetElement("Type", "Picture");
                                    Identified=true; found=true;
                            }
                        }
                    }
                }

                //  AOL Art File 4a 47 04|03 0e

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4a)
                    {
                        if (Chunk[1] == 0x47)
                        {
                            if (Chunk[2] == 0x04 || Chunk[2] == 0x03)
                            {
                                if (Chunk[3] == 0x0e)
                                {
                                    CFI.SetElement("Confirm", ".ART");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "AOL Art File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  National Imagery Transmission Format (NITF) file  4E 49 54 46 30

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4e)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    if (Chunk[4] == 0x30)
                                    {
                                        CFI.SetElement("Confirm", ".NTF");
                                        CFI.SetElement("Type", "Picture");
                                        CFI.AddElement("Details", "National Imagery Transmission Format NITF File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Tagged Image File Format (TIFF) 49 49 2A 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x2a)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".TIFF");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Tagged Image File Format TIFF File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Tagged Image File Format (TIFF) 4D 4D 00 2A|2B

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x4d)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x2a || Chunk[3] == 0x2b)
                                {
                                    CFI.SetElement("Confirm", ".TIFF");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Tagged Image File Format TIFF File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                    //  Harvard Grahpics symbol graphic 41 4D 59 4F

                    if (ChunkSize > 4 && !found)
                    {
                        if (Chunk[0] == 0x41)
                        {
                            if (Chunk[1] == 0x4D)
                            {
                                if (Chunk[2] == 0x59)
                                {
                                    if (Chunk[3] == 0x4F)
                                    {
                                        CFI.SetElement("Confirm", ".SYW");
                                        CFI.SetElement("Type", "Picture");
                                        CFI.AddElement("Details", "Harvard Garphics Symbol Graphic File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }


                    //  Corel Binary Metafile

                    if (ChunkSize > 4 && !found)
                    {
                        if (Chunk[0] == 0x43)
                        {
                            if (Chunk[1] == 0x4D)
                            {
                                if (Chunk[2] == 0x58)
                                {
                                    if (Chunk[3] == 0x31)
                                    {
                                        CFI.SetElement("Confirm", ".CLB");
                                        CFI.SetElement("Type", "Picture");
                                        CFI.AddElement("Details", "Corel Binary Metafile");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }

                    // Canon digital Camera 49 49 1A 00 00 00 48 45 41 50 43 43 44 52 02 00

                    if (ChunkSize > 20 && !found)
                    {
                        if (Chunk[0] == 0x49)
                        {
                            if (Chunk[1] == 0x49)
                            {
                                if (Chunk[2] == 0x1a)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x00)
                                        {
                                            if (Chunk[5] == 0x00)
                                            {
                                                if (Chunk[6] == 0x48)
                                                {
                                                    if (Chunk[7] == 0x45)
                                                    {
                                                        if (Chunk[8] == 0x41)
                                                        {
                                                            if (Chunk[9] == 0x50)
                                                            {
                                                                if (Chunk[10] == 0x43)
                                                                {
                                                                    if (Chunk[11] == 0x44)
                                                                    {
                                                                        if (Chunk[12] == 0x52)
                                                                        {
                                                                            if (Chunk[13] == 0x02)
                                                                            {
                                                                                if (Chunk[14] == 0x00)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".CRW");
                                                                                    CFI.SetElement("Type", "Picture");
                                                                                    CFI.AddElement("Details", "Canon Digital Camera File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Canon digital Camera CR2 49 49 2A 00 10 00 00 00 43 52

                    if (ChunkSize > 10 && !found)
                    {
                        if (Chunk[0] == 0x49)
                        {
                            if (Chunk[1] == 0x49)
                            {
                                if (Chunk[2] == 0x2a)
                                {
                                    if (Chunk[3] == 0x00)
                                    {
                                        if (Chunk[4] == 0x10)
                                        {
                                            if (Chunk[5] == 0x00)
                                            {
                                                if (Chunk[6] == 0x00)
                                                {
                                                    if (Chunk[7] == 0x00)
                                                    {
                                                        if (Chunk[8] == 0x43)
                                                        {
                                                            if (Chunk[9] == 0x52)
                                                            {
                                                                CFI.SetElement("Confirm", ".CR2");
                                                                CFI.SetElement("Type", "Picture");
                                                                CFI.AddElement("Details", "Canon Digital Camera File");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    //  Identify JP-2000 file 00 00 00 0c 6a 50 20 20 0d 0a

                    if (ChunkSize > 10 && !found)
                    {
                        if (Chunk[0] == 0x00)
                        {
                            if (Chunk[1] == 0x00)
                            {
                                if (Chunk[2] == 0x00)
                                {
                                    if (Chunk[3] == 0x0C)
                                    {
                                        if (Chunk[4] == 0x6A)
                                        {
                                            if (Chunk[5] == 0x50)
                                            {
                                                if (Chunk[6] == 0x20)
                                                {
                                                    if (Chunk[7] == 0x20)
                                                    {
                                                        if (Chunk[8] == 0x0D)
                                                        {
                                                            if (Chunk[9] == 0x0A)
                                                            {
                                                                CFI.SetElement("Confirm", ".JP2");
                                                                CFI.SetElement("Type", "Picture");
                                                                CFI.AddElement("Details", "JP-2000 Image File");
                                                                Identified=true; found=true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a GIF file 47 49 46 38 39 61

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x47)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x46)
                            {
                                if (Chunk[3] == 0x38)
                                {
                                    if (Chunk[4] == 0x39)
                                    {
                                        if (Chunk[5] == 0x61)
                                        {
                                            CFI.SetElement("Confirm", ".GIF");
                                            CFI.SetElement("Type", "Picture");
                                            CFI.AddElement("Details", "Graphics Interchange Format File");
                                            Identified=true; found=true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a PNG file 89 50 4E 47 

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x89)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x4E)
                            {
                                if (Chunk[3] == 0x47)
                                {
                                    CFI.SetElement("Confirm", ".PNG");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Portable Network Graphics File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Photoshop Image File 38 42 50 53

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x38)
                    {
                        if (Chunk[1] == 0x42)
                        {
                            if (Chunk[2] == 0x50)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    CFI.SetElement("Confirm", ".PSD");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Adobe Photoshop Image File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a FITS graphics file 53 49 4d 50 4c 45

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[13] == 0x53)
                    {
                        if (Chunk[14] == 0x49)
                        {
                            if (Chunk[15] == 0x4D)
                            {
                                if (Chunk[16] == 0x50)
                                {
                                    if (Chunk[17] == 0x4C)
                                    {
                                        if (Chunk[18] == 0x45)
                                        {
                                            CFI.SetElement("Confirm", ".FITS");
                                            CFI.SetElement("Type", "Picture");
                                            CFI.AddElement("Details", "Flexible Image Transport System File");
                                            Identified=true; found=true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify Graphics Kernel System file 47 4b 53 4d

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x47)
                    {
                        if (Chunk[1] == 0x4B)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x4D)
                                {
                                    CFI.SetElement("Confirm", ".GKS");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Graphics Kernel System File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Identify View file 56 49 45 57

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x56)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x57)
                                {
                                    CFI.SetElement("Confirm", ".PM");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "View Image File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  FLI FLIC file 00 11 AF

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x11)
                        {
                            if (Chunk[2] == 0xAF)
                            {
                                CFI.SetElement("Confirm", ".FLI");
                                CFI.SetElement("Type", "Picture");
                                CFI.AddElement("Details", "FLI FLIC Image File");
                                Identified=true; found=true;
                            }
                        }
                    }
                }

                //  Identify IMG 00 01 00 80 00 01 00 01 01

                if (ChunkSize > 9 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x80)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x01)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x01)
                                                {
                                                    if (Chunk[8] == 0x01)
                                                    {
                                                        CFI.SetElement("Confirm", ".IMG");
                                                        CFI.SetElement("Type", "Picture");
                                                        CFI.AddElement("Details", "IMG Image File");
                                                        Identified=true; found=true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Radiance High Tree Range image file 23 3F 52 41 44 49 41 4E 43 45 0A

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x23)
                    {
                        if (Chunk[1] == 0x3f)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x41)
                                {
                                    if (Chunk[4] == 0x44)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x42)
                                            {
                                                if (Chunk[7] == 0x4e)
                                                {
                                                    if (Chunk[8] == 0x43)
                                                    {
                                                        if (Chunk[9] == 0x45)
                                                        {
                                                            if (Chunk[10] == 0x0A)
                                                            {
                                                                CFI.SetElement("Confirm", ".HDR");
                                                                CFI.SetElement("Type", "Picture");
                                                                CFI.AddElement("Details", "Radiance High Tree Range Image File");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  SGI RGB Bitmap file 01 da 01 01 00 03

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0xDA)
                        {
                            if (Chunk[2] == 0x01)
                            {
                                if (Chunk[3] == 0x01)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x03)
                                        {
                                            CFI.SetElement("Confirm", ".RGB");
                                            CFI.SetElement("Type", "Picture");
                                            CFI.AddElement("Details", "Silicon Graphics RGB Bitmap File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  DRW Micrografx vector graphics file 01 ff 02 04 03 02

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0xFF)
                        {
                            if (Chunk[2] == 0x02)
                            {
                                if (Chunk[3] == 0x04)
                                {
                                    if (Chunk[4] == 0x03)
                                    {
                                        if (Chunk[5] == 0x02)
                                        {
                                            CFI.SetElement("Confirm", ".DRW");
                                            CFI.SetElement("Type", "Picture");
                                            CFI.AddElement("Details", "DRW Micrografx Vector Graphics File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  PCX ZSOFT Paintbrush File 0a 02|03|05 01 01

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x0A)
                    {
                        if (Chunk[1] == 0x02 || Chunk[1] == 0x03 || Chunk[1] == 0x05)
                        {
                            if (Chunk[2] == 0x01)
                            {
                                if (Chunk[3] == 0x01)
                                {
                                    CFI.SetElement("Confirm", ".PCX");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "PCX ZSoft Paintbrush File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  GIMP Pattern File 47 50 41 54

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x47)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0x54)
                                {
                                    CFI.SetElement("Confirm", ".PAT");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "GNU Image Manipulation File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a Icon Class 00 00 01 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x01)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".ICO");
                                    CFI.SetElement("Type", "Picture");
                                    CFI.AddElement("Details", "Icon Graphic");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Corel Photopaint File 43 50 54 37 46 49 4C 45

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x37)
                                {
                                    if (Chunk[4] == 0x46)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x4c)
                                            {
                                                if (Chunk[7] == 0x45)
                                                {
                                                    CFI.SetElement("Confirm", ".CPT");
                                                    CFI.SetElement("Type", "Picture");
                                                    CFI.AddElement("Details", "Corel Photopaint File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Corel Photopaint File 43 50 54 46 49 4C 45

                if (ChunkSize > 7 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    if (Chunk[4] == 0x49)
                                    {
                                        if (Chunk[5] == 0x4c)
                                        {
                                            if (Chunk[6] == 0x45)
                                            {
                                                CFI.SetElement("Confirm", ".CPT");
                                                CFI.SetElement("Type", "Picture");
                                                CFI.AddElement("Details", "Corel Photopaint File");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Portable Graymap Graphic 50 35 0A

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x35)
                        {
                            if (Chunk[2] == 0x0a)
                            {
                                CFI.SetElement("Confirm", ".PGM");
                                CFI.SetElement("Type", "Picture");
                                CFI.AddElement("Details", "Portable Graymap Graphic");
                                Identified =true; found = true;
                            }
                        }
                    }
                }

                //  ChromaGraph Graphics Card Bitmap Graphics file  50 49 43 54 00 08

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x54)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x08)
                                        {
                                            CFI.SetElement("Confirm", ".IMG");
                                            CFI.SetElement("Type", "Picture");
                                            CFI.AddElement("Details", "ChromaGraph Graphics Card Bitmap Graphics File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Smartdraw Drawing File  53 4D 41 52 54 44 52 57

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x4d)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0x52)
                                {
                                    if (Chunk[4] == 0x54)
                                    {
                                        if (Chunk[5] == 0x44)
                                        {
                                            if (Chunk[6] == 0x52)
                                            {
                                                if (Chunk[7] == 0x57)
                                                {
                                                    CFI.SetElement("Confirm", ".SDR");
                                                    CFI.SetElement("Type", "Picture");
                                                    CFI.AddElement("Details", "Smartdraw Drawing File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Photoshop Custom Shape 63 75 73 68 00 00 00 02 00 00 00

                if (ChunkSize > 11 && !found) 
                {
                    if (Chunk[0] == 0x63)
                    {
                        if (Chunk[1] == 0x75)
                        {
                            if (Chunk[2] == 0x73)
                            {
                                if (Chunk[3] == 0x68)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x02)
                                                {
                                                    if (Chunk[8] == 0x00)
                                                    {
                                                        if (Chunk[9] == 0x00)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {

                                                                CFI.SetElement("Confirm", ".CSH");
                                                                CFI.SetElement("Type", "Picture");
                                                                CFI.AddElement("Details", "Adobe Photoshop Custom Shape");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// AUDIO FILE FORMATS

                //  Identify a WAV file 52 49 46 46 32

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x46)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    if (Chunk[4] == 0x32)
                                    {
                                        CFI.SetElement("Confirm", ".WAV");
                                        CFI.SetElement("Type", "Audio");
                                        CFI.AddElement("Details", "Wave Audio File");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Audacity Audio File 64 6E 73 2E

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x64)
                    {
                        if (Chunk[1] == 0x6e)
                        {
                            if (Chunk[2] == 0x73)
                            {
                                if (Chunk[3] == 0x2e)
                                {
                                    CFI.SetElement("Confirm", ".AU");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "Audacity Audio File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }


                //  Adaptive Multi-Rate ACELP  23 21 41 4D 52

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x23)
                    {
                        if (Chunk[1] == 0x21)
                        {
                            if (Chunk[2] == 0x41)
                            {
                                if (Chunk[3] == 0x4D)
                                {
                                    if (Chunk[4] == 0x52)
                                    {
                                        CFI.SetElement("Confirm", ".AMR");
                                        CFI.SetElement("Type", "Audio");
                                        CFI.AddElement("Details", "Adaptive Multi-Rate ACELP Audio File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify MP3 file 49 44 33 03

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x33)
                            {
                                if (Chunk[3] == 0x03)
                                {
                                    CFI.SetElement("Confirm", ".MP3");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "MP3 Audio File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Identify a M4A file 00 00 00 20 66 74 79 70 4d 34 41 20

                if (ChunkSize > 12 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x20)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x4d)
                                                    {
                                                        if (Chunk[9] == 0x34)
                                                        {
                                                            if (Chunk[10] == 0x41)
                                                            {
                                                                if (Chunk[11] == 0x20)
                                                                {
                                                                    CFI.SetElement("Confirm", ".M4A");
                                                                    CFI.SetElement("Type", "Audio");
                                                                    CFI.AddElement("Details", "Music 4 All Audio File");
                                                                    Identified=true; found=true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  DSS Digital Speech Standard file 02 64 73 73

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x02)
                    {
                        if (Chunk[1] == 0x64)
                        {
                            if (Chunk[2] == 0x73)
                            {
                                if (Chunk[3] == 0x73)
                                {

                                    CFI.SetElement("Confirm", ".DSS");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "Digital Speech Standard Audio File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  ReadPlayer Audio File 2e 52 4d 46    2E 52 4D 46 00 00 00 12 00

                if (ChunkSize > 13 && !found)
                {
                    if (Chunk[0] == 0x2e)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    if (Chunk[4] == 0x2e)
                                    {
                                        if (Chunk[5] == 0x52)
                                        {
                                            if (Chunk[6] == 0x4d)
                                            {
                                                if (Chunk[7] == 0x46)
                                                {
                                                    if (Chunk[8] == 0x00)
                                                    {
                                                        if (Chunk[9] == 0x00)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                if (Chunk[11] == 0x12)
                                                                {
                                                                    if (Chunk[12] == 0x00)
                                                                    {
                                                                        CFI.SetElement("Confirm", ".RA");
                                                                        CFI.SetElement("Type", "Audio");
                                                                        CFI.AddElement("Details", "Real RealPlayer Audio File");
                                                                        Identified=true; found = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  RealAudio Streaming Media File  2E 72 61 FD 00

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x2e)
                    {
                        if (Chunk[1] == 0x72)
                        {
                            if (Chunk[2] == 0x61)
                            {
                                if (Chunk[3] == 0xfd)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        CFI.SetElement("Confirm", ".RA");
                                        CFI.SetElement("Type", "Audio");
                                        CFI.AddElement("Details", "Real RealAudio Streaming Media File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  AU Audio File  2E 73 6E 64

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x2E)
                    {
                        if (Chunk[1] == 0x73)
                        {
                            if (Chunk[2] == 0x6E)
                            {
                                if (Chunk[3] == 0x64)
                                {

                                    CFI.SetElement("Confirm", ".AU");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "AU Audio File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x2E)
                    {
                        if (Chunk[1] == 0x73)
                        {
                            if (Chunk[2] == 0x6E)
                            {
                                if (Chunk[3] == 0x64)
                                {

                                    CFI.SetElement("Confirm", ".AU");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "AU Audio File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                // Audio Interchange File 46 4F 52 4D 00

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x46)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x4d)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        CFI.SetElement("Confirm", ".AIFF");
                                        CFI.SetElement("Type", "Audio");
                                        CFI.AddElement("Details", "Audio Interchange File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Sprint Music Store Audio File 49 44 33 03 00 00 00

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x49)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x33)
                            {
                                if (Chunk[3] == 0x03)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                CFI.SetElement("Confirm", ".KOZ");
                                                CFI.SetElement("Type", "Audio");
                                                CFI.AddElement("Details", "Sprint Music Store Audio File");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // MIDI (Yoohoo!)  4D 54 68 64

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x54)
                        {
                            if (Chunk[2] == 0x68)
                            {
                                if (Chunk[3] == 0x64)
                                {

                                    CFI.SetElement("Confirm", ".MIDI");
                                    CFI.SetElement("Type", "Audio");
                                    CFI.AddElement("Details", "MIDI Audio File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }


                // NES Sound File (8 bit r0x0rz) 4E 45 53 4D 1A 01

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4e)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x4d)
                                {
                                    if (Chunk[4] == 0x1a)
                                    {
                                        if (Chunk[5] == 0x01)
                                        {
                                            CFI.SetElement("Confirm", ".NSF");
                                            CFI.SetElement("Type", "Audio");
                                            CFI.AddElement("Details", "Nintendo Entertainment System Audio File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Yamaha Synthetic Mobile Application Format 4D 4D 4D 44 00 00

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x4d)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x44)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {

                                            CFI.SetElement("Confirm", ".MMF");
                                            CFI.SetElement("Type", "Audio");
                                            CFI.AddElement("Details", "Yamaha Synthetic Mobile Application Format Audio File");
                                            Identified=true; found = true;

                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Sony Compressed Voice File 4D 53 5F 56 4F 49 43 45

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x5f)
                            {
                                if (Chunk[3] == 0x56)
                                {
                                    if (Chunk[4] == 0x4f)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x43)
                                            {
                                                if (Chunk[7] == 0x45)
                                                {
                                                    CFI.SetElement("Confirm", ".DVF");
                                                    CFI.SetElement("Type", "Audio");
                                                    CFI.AddElement("Details", "Sony Compressed Voice File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  FLAC Lossless Audio Codec File  66 4C 61 43 00 00 00 22

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x66)
                    {
                        if (Chunk[1] == 0x4c)
                        {
                            if (Chunk[2] == 0x61)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x22)
                                                {
                                                    CFI.SetElement("Confirm", ".FLAC");
                                                    CFI.SetElement("Type", "Audio");
                                                    CFI.AddElement("Details", "Free Lossless Audio Codec");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

//  DATABASE FILE FORMATS

                //  Identify a Microsoft Access file 4A 65 74 20 44 42 (Offset +13)

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[13] == 0x4A)
                    {
                        if (Chunk[14] == 0x65)
                        {
                            if (Chunk[15] == 0x74)
                            {
                                if (Chunk[16] == 0x20)
                                {
                                    if (Chunk[17] == 0x44)
                                    {
                                        if (Chunk[18] == 0x42)
                                        {
                                            CFI.SetElement("Confirm", ".MDB");
                                            CFI.SetElement("Type", "Database");
                                            CFI.AddElement("Details", "Microsoft Access Database File");
                                            Identified=true; found=true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a SQLite File 53 51 4C 69 74 65

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x51)
                        {
                            if (Chunk[2] == 0x4C)
                            {
                                if (Chunk[3] == 0x69)
                                {
                                    if (Chunk[4] == 0x74)
                                    {
                                        if (Chunk[5] == 0x65)
                                        {
                                            CFI.SetElement("Confirm", ".SQLite");
                                            CFI.SetElement("Type", "Database");
                                            CFI.AddElement("Details", "SQLite Database File");
                                            Identified=true; found=true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  NSF Lotus Notes Database 1a 00 00 04 00 00

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x1a)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x04)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            CFI.SetElement("Confirm", ".NSF");
                                            CFI.SetElement("Type", "Database");
                                            CFI.AddElement("Details", "IBM Lotus Notes Database File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a ACCDB (ACE DB) file 00 01 00 00 53 74 61 6e 64 61 72 64 20 41 43 45 20 44 42

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x53)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x61)
                                            {
                                                if (Chunk[7] == 0x6e)
                                                {
                                                    if (Chunk[8] == 0x64)
                                                    {
                                                        if (Chunk[9] == 0x61)
                                                        {
                                                            if (Chunk[10] == 0x72)
                                                            {
                                                                if (Chunk[11] == 0x64)
                                                                {
                                                                    if (Chunk[12] == 0x20)
                                                                    {
                                                                        if (Chunk[13] == 0x41)
                                                                        {
                                                                            if (Chunk[14] == 0x43)
                                                                            {
                                                                                if (Chunk[15] == 0x45)
                                                                                {
                                                                                    if (Chunk[16] == 0x20)
                                                                                    {
                                                                                        if (Chunk[17] == 0x44)
                                                                                        {
                                                                                            if (Chunk[18] == 0x42)
                                                                                            {
                                                                                                    CFI.SetElement("Confirm", ".ACCDB");
                                                                                                    CFI.SetElement("Type", "Database");
                                                                                                    CFI.AddElement("Details", "Ace Database File");
                                                                                                    Identified=true; found=true;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a MDB (JET DB) file 00 01 00 00 53 74 61 6e 64 61 72 64 20 4a 65 74 20 44 42

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x53)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x61)
                                            {
                                                if (Chunk[7] == 0x6e)
                                                {
                                                    if (Chunk[8] == 0x64)
                                                    {
                                                        if (Chunk[9] == 0x61)
                                                        {
                                                            if (Chunk[10] == 0x72)
                                                            {
                                                                if (Chunk[11] == 0x64)
                                                                {
                                                                    if (Chunk[12] == 0x20)
                                                                    {
                                                                        if (Chunk[13] == 0x4a)
                                                                        {
                                                                            if (Chunk[14] == 0x65)
                                                                            {
                                                                                if (Chunk[15] == 0x74)
                                                                                {
                                                                                    if (Chunk[16] == 0x20)
                                                                                    {
                                                                                        if (Chunk[17] == 0x44)
                                                                                        {
                                                                                            if (Chunk[18] == 0x42)
                                                                                            {
                                                                                                CFI.SetElement("Confirm", ".MDB");
                                                                                                CFI.SetElement("Type", "Database");
                                                                                                CFI.AddElement("Details", "Microsoft Jet Database File");
                                                                                                Identified=true; found=true;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Psion Series 3 Database file  4F 50 4C 44 61 74 61 62 61 73 65 46 69 6C 65

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x4f)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x44)
                                {
                                    if (Chunk[4] == 0x61)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x61)
                                            {
                                                if (Chunk[7] == 0x62)
                                                {
                                                    if (Chunk[8] == 0x61)
                                                    {
                                                        if (Chunk[9] == 0x73)
                                                        {
                                                            if (Chunk[10] == 0x65)
                                                            {
                                                                if (Chunk[11] == 0x46)
                                                                {
                                                                    if (Chunk[12] == 0x69)
                                                                    {
                                                                        if (Chunk[13] == 0x6c)
                                                                        {
                                                                            if (Chunk[14] == 0x65)
                                                                            {
                                                                                CFI.SetElement("Confirm", ".DBF");
                                                                                CFI.SetElement("Type", "Database");
                                                                                CFI.AddElement("Details", "Psion Series 3 Database File");
                                                                                Identified=true; found = true;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Firebird and Interbase database files 01 00 39 30

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x39)
                            {
                                if (Chunk[3] == 0x30)
                                {
                                    CFI.SetElement("Confirm", "Interbase");
                                    CFI.SetElement("Type", "Database");
                                    CFI.AddElement("Details", "Firebird or Interbase Database File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Microsoft Active Directory xx xx xx xx EF CD AB 89

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0xef)
                    {
                        if (Chunk[5] == 0xcd)
                        {
                            if (Chunk[6] == 0xab)
                            {
                                if (Chunk[7] == 0x89)
                                {
                                    CFI.SetElement("Confirm", "Active Directory Database");
                                    CFI.SetElement("Type", "Database");
                                    CFI.AddElement("Details", "Microsoft Active Directory Database");
                                    Identified = true; found = true;
                                }
                            }
                        }
                    }
                }


                //  Microsoft SQL Server 2000 Database 01 0f 00 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0x0F)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".MDF");
                                    CFI.SetElement("Type", "Database");
                                    CFI.AddElement("Details", "Microsoft SQL Server 2000 Database File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }


                //  ADX Approach Index File 03 00 00 00 41 50 50 52

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x03)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x41)
                                    {
                                        if (Chunk[5] == 0x50)
                                        {
                                            if (Chunk[6] == 0x50)
                                            {
                                                if (Chunk[7] == 0x52)
                                                {
                                                    CFI.SetElement("Confirm", ".ADX");
                                                    CFI.SetElement("Type", "Database");
                                                    CFI.AddElement("Details", "APX Approach Database File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  AVG6 Integrity Database File 41 56 47 36 5F 49 6E 74 65 67 72 69 74 79 5F 44 61 74 61 62 61 73 65

                if (ChunkSize > 23 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x56)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x36)
                                {
                                    if (Chunk[4] == 0x5f)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x6e)
                                            {
                                                if (Chunk[7] == 0x74)
                                                {
                                                    if (Chunk[8] == 0x65)
                                                    {
                                                        if (Chunk[9] == 0x67)
                                                        {
                                                            if (Chunk[10] == 0x72)
                                                            {
                                                                if (Chunk[11] == 0x69)
                                                                {
                                                                    if (Chunk[12] == 0x74)
                                                                    {
                                                                        if (Chunk[13] == 0x79)
                                                                        {
                                                                            if (Chunk[14] == 0x5f)
                                                                            {
                                                                                if (Chunk[15] == 0x44)
                                                                                {
                                                                                    if (Chunk[16] == 0x61)
                                                                                    {
                                                                                        if (Chunk[17] == 0x74)
                                                                                        {
                                                                                            if (Chunk[18] == 0x61)
                                                                                            {
                                                                                                if (Chunk[19] == 0x62)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x61)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x73)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x65)
                                                                                                            {
                                                                                                                CFI.SetElement("Confirm", ".DAT");
                                                                                                                CFI.SetElement("Type", "Database");
                                                                                                                CFI.AddElement("Details", "AVG6 Integrity Database File");
                                                                                                                Identified=true; found = true;
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  WhereIsIt Catalog File 43 61 74 61 6C 6F 67 20 33 2E 30 30 00

                if (ChunkSize > 13 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x61)
                        {
                            if (Chunk[2] == 0x74)
                            {
                                if (Chunk[3] == 0x61)
                                {
                                    if (Chunk[4] == 0x6c)
                                    {
                                        if (Chunk[5] == 0x6f)
                                        {
                                            if (Chunk[6] == 0x67)
                                            {
                                                if (Chunk[7] == 0x20)
                                                {
                                                    if (Chunk[8] == 0x33)
                                                    {
                                                        if (Chunk[9] == 0x2e)
                                                        {
                                                            if (Chunk[10] == 0x30)
                                                            {
                                                                if (Chunk[11] == 0x30)
                                                                {
                                                                    if (Chunk[12] == 0x00)
                                                                    {
                                                                        CFI.SetElement("Confirm", ".CTF");
                                                                        CFI.SetElement("Type", "Database");
                                                                        CFI.AddElement("Details", "WhereIsIt Catalog File");
                                                                        Identified=true; found = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Fiasco Database Definition File  46 44 42 48 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x46)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x42)
                            {
                                if (Chunk[3] == 0x48)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        CFI.SetElement("Confirm", ".FDB");
                                        CFI.SetElement("Type", "Database");
                                        CFI.AddElement("Details", "Fiasco Database Definition File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  DB2 conversion file 53 51 4C 4F 43 4F 4E 56 48 44 00 00 31 2E 30 00

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x51)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x4f)
                                {
                                    if (Chunk[4] == 0x43)
                                    {
                                        if (Chunk[5] == 0x4f)
                                        {
                                            if (Chunk[6] == 0x4e)
                                            {
                                                if (Chunk[7] == 0x56)
                                                {
                                                    if (Chunk[8] == 0x48)
                                                    {
                                                        if (Chunk[9] == 0x44)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                if (Chunk[11] == 0x00)
                                                                {
                                                                    if (Chunk[12] == 0x31)
                                                                    {
                                                                        if (Chunk[13] == 0x2e)
                                                                        {
                                                                            if (Chunk[14] == 0x30)
                                                                            {
                                                                                if (Chunk[15] == 0x00)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".CNV");
                                                                                    CFI.SetElement("Type", "Database");
                                                                                    CFI.AddElement("Details", "DB2 Conversion Database File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


//   VIDEO FORMATS

                //  Identify a MPEG file 00 00 01 BA 21

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x01)
                            {
                                if (Chunk[3] == 0xBA)
                                {
                                    if (Chunk[4] == 0x21)
                                    {
                                        CFI.SetElement("Confirm", ".MPG");
                                        CFI.SetElement("Type", "Video");
                                        CFI.AddElement("Details", "MPEG Video File");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File  6D 6F 6F 76 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x6d)
                    {
                        if (Chunk[5] == 0x6f)
                        {
                            if (Chunk[6] == 0x6f)
                            {
                                if (Chunk[7] == 0x76)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File  0x66-72-65-65 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x66)
                    {
                        if (Chunk[5] == 0x72)
                        {
                            if (Chunk[6] == 0x65)
                            {
                                if (Chunk[7] == 0x65)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File 0x6D-64-61-74 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x6d)
                    {
                        if (Chunk[5] == 0x64)
                        {
                            if (Chunk[6] == 0x61)
                            {
                                if (Chunk[7] == 0x74)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File 0x77-69-64-65 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x77)
                    {
                        if (Chunk[5] == 0x69)
                        {
                            if (Chunk[6] == 0x64)
                            {
                                if (Chunk[7] == 0x65)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File 0x70-6E-6F-74 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x70)
                    {
                        if (Chunk[5] == 0x6e)
                        {
                            if (Chunk[6] == 0x6f)
                            {
                                if (Chunk[7] == 0x74)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Quicktime Movie File 0x73-6B-69-70 + 4 byte offset

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[4] == 0x73)
                    {
                        if (Chunk[5] == 0x6b)
                        {
                            if (Chunk[6] == 0x69)
                            {
                                if (Chunk[7] == 0x70)
                                {
                                    CFI.SetElement("Confirm", ".MOV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Quicktime Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Flash Video File 46 4C 56 01

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x46)
                    {
                        if (Chunk[1] == 0x4c)
                        {
                            if (Chunk[2] == 0x56)
                            {
                                if (Chunk[3] == 0x01)
                                {
                                    CFI.SetElement("Confirm", ".FLV");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Flash Movie File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a MPEG-4 v1 file 00 00 00 14 66 74 79 70 33 67 70

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x14)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x33)
                                                    {
                                                        if (Chunk[9] == 0x67)
                                                        {
                                                            if (Chunk[10] == 0x70)
                                                            {
                                                                CFI.SetElement("Confirm", ".MPG4V1");
                                                                CFI.SetElement("Type", "Video");
                                                                CFI.AddElement("Details", "MPG4 v1 Movie File");
                                                                Identified=true; found=true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Ogg Vorbis Codec compressed multimedia file  4F 67 67 53 00 02 00 00 00 00 00 00 00 00

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x4f)
                    {
                        if (Chunk[1] == 0x67)
                        {
                            if (Chunk[2] == 0x67)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x02)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    if (Chunk[8] == 0x00)
                                                    {
                                                        if (Chunk[9] == 0x00)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                CFI.SetElement("Confirm", ".OGG");
                                                                CFI.SetElement("Type", "Video");
                                                                CFI.AddElement("Details", "Ogg Vorbis Movie File");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a MPEG-4 file 00 00 00 14 66 74 79 70 33 67 70

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x14)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x33)
                                                    {
                                                        if (Chunk[9] == 0x67)
                                                        {
                                                            if (Chunk[10] == 0x70)
                                                            {
                                                                CFI.SetElement("Confirm", ".MPG");
                                                                CFI.SetElement("Type", "Video");
                                                                CFI.AddElement("Details", "MPG-4 Movie File");
                                                                Identified=true; found=true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a M4P file 00 00 00 18 66 74 79 70 6d 70 34 32

                if (ChunkSize > 12 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x18)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x6d)
                                                    {
                                                        if (Chunk[9] == 0x70)
                                                        {
                                                            if (Chunk[10] == 0x34)
                                                            {
                                                                if (Chunk[11] == 0x32)
                                                                {
                                                                    CFI.SetElement("Confirm", ".M4V");
                                                                    CFI.SetElement("Type", "Video");
                                                                    CFI.AddElement("Details", "M4V Movie File");
                                                                    Identified=true; found=true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a MP4 file 00 00 00 1c 66 74 79 70 4d 53 4e 56 01 29 00 46 4d 53 4e 56 6d 70 34 32

                if (ChunkSize > 24 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x1c)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x4d)
                                                    {
                                                        if (Chunk[9] == 0x53)
                                                        {
                                                            if (Chunk[10] == 0x4e)
                                                            {
                                                                if (Chunk[11] == 0x56)
                                                                {
                                                                    if (Chunk[12] == 0x01)
                                                                    {
                                                                        if (Chunk[13] == 0x29)
                                                                        {
                                                                            if (Chunk[14] == 0x00)
                                                                            {
                                                                                if (Chunk[15] == 0x46)
                                                                                {
                                                                                    if (Chunk[16] == 0x4d) // 53 4e 56 6d 70 34 32
                                                                                    {
                                                                                        if (Chunk[17] == 0x53)
                                                                                        {
                                                                                            if (Chunk[18] == 0x4e)
                                                                                            {
                                                                                                if (Chunk[19] == 0x56)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x6d)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x70)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x34)
                                                                                                            {
                                                                                                                if (Chunk[23] == 0x32)
                                                                                                                {
                                                                                                                    CFI.SetElement("Confirm", ".MP4");
                                                                                                                    CFI.SetElement("Type", "Video");
                                                                                                                    CFI.AddElement("Details", "MP4 Movie File");
                                                                                                                    Identified=true; found=true;
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a MOV Quicktime file 00 00 00 14 66 74 79 70 71 74 20 20

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x14)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x71)
                                                    {
                                                        if (Chunk[9] == 0x74)
                                                        {
                                                            if (Chunk[10] == 0x20)
                                                            {
                                                                if (Chunk[11] == 0x20)
                                                                {
                                                                    CFI.SetElement("Confirm", ".MOV");
                                                                    CFI.SetElement("Type", "Video");
                                                                    CFI.AddElement("Details", "Quicktime Movie File");
                                                                    Identified=true; found=true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Realvideo

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x2E)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x54)
                                {

                                    CFI.SetElement("Confirm", ".REC");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Real RealVideo Recording Movie File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x2E)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x4D)
                            {
                                if (Chunk[3] == 0x46)
                                {

                                    CFI.SetElement("Confirm", ".RMVB");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Real RealMedia Video File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x2E)
                    {
                        if (Chunk[1] == 0x72)
                        {
                            if (Chunk[2] == 0x61)
                            {
                                if (Chunk[3] == 0xFD)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        CFI.SetElement("Confirm", ".RAY");
                                        CFI.SetElement("Type", "Video");
                                        CFI.AddElement("Details", "Real RealMedia Video File");
                                        Identified=true; found=true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify 3GPP 1 file 00 00 00 14 66 74 79 70 33 67 70

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x14)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x33)
                                                    {
                                                        if (Chunk[9] == 0x67)
                                                        {
                                                            if (Chunk[10] == 0x70)
                                                            {

                                                                CFI.SetElement("Confirm", ".3GPP");
                                                                CFI.SetElement("Type", "Video");
                                                                Identified=true; found=true;
                                                                CFI.AddElement("Details", "3GPP Video File");
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


                //  Identify 3GPP 1 file 00 00 00 nn 66 74 79 70 33 67 70

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x20)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x79)
                                            {
                                                if (Chunk[7] == 0x70)
                                                {
                                                    if (Chunk[8] == 0x33)
                                                    {
                                                        if (Chunk[9] == 0x67)
                                                        {
                                                            if (Chunk[10] == 0x70)
                                                            {
                                                                CFI.SetElement("Confirm", ".3GPP2");
                                                                CFI.SetElement("Type", "Video");
                                                                CFI.AddElement("Details", "3GPP2 Video File");
                                                                Identified=true; found=true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Matroska stream file 1a 45 df a3 93 42 82 88 6d 61 74 72 6f 73 6b 61

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x1a)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0xdf)
                            {
                                if (Chunk[3] == 0xa3)
                                {
                                    if (Chunk[4] == 0x93)
                                    {
                                        if (Chunk[5] == 0x42)
                                        {
                                            if (Chunk[6] == 0x82)
                                            {
                                                if (Chunk[7] == 0x88)
                                                {
                                                    if (Chunk[8] == 0x6d)
                                                    {
                                                        if (Chunk[9] == 0x61)
                                                        {
                                                            if (Chunk[10] == 0x74)
                                                            {
                                                                if (Chunk[11] == 0x72)
                                                                {
                                                                    if (Chunk[12] == 0x6f)
                                                                    {
                                                                        if (Chunk[13] == 0x73)
                                                                        {
                                                                            if (Chunk[14] == 0x6b)
                                                                            {
                                                                                if (Chunk[15] == 0x61)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".MKV");
                                                                                    CFI.SetElement("Type", "Video");
                                                                                    CFI.AddElement("Details", "Matroska Video File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Microsoft Windows Media Audio/Video File  30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x30)
                    {
                        if (Chunk[1] == 0x26)
                        {
                            if (Chunk[2] == 0xb2)
                            {
                                if (Chunk[3] == 0x75)
                                {
                                    if (Chunk[4] == 0x8e)
                                    {
                                        if (Chunk[5] == 0x66)
                                        {
                                            if (Chunk[6] == 0xcf)
                                            {
                                                if (Chunk[7] == 0x11)
                                                {
                                                    if (Chunk[8] == 0xa6)
                                                    {
                                                        if (Chunk[9] == 0xd9)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                if (Chunk[11] == 0xaa)
                                                                {
                                                                    if (Chunk[12] == 0x00)
                                                                    {
                                                                        if (Chunk[13] == 0x62)
                                                                        {
                                                                            if (Chunk[14] == 0xce)
                                                                            {
                                                                                if (Chunk[15] == 0x6c)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".ASF");
                                                                                    CFI.SetElement("Type", "Video");
                                                                                    CFI.AddElement("Details", "Microsoft Windows Audio/Video File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


                //  RealPlayer Video File 2e 52 45 43

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x2e)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                        CFI.SetElement("Confirm", ".IVR");
                                        CFI.SetElement("Type", "Video");
                                        CFI.AddElement("Details", "Real RealMedia Video File");
                                        Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  RealPlayer Streaming Media File 2e 52 4d 46

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x2e)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".RMVB");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "Real RealMedia Video File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  DVR-Studio stream file 44 56 44

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x44)
                    {
                        if (Chunk[1] == 0x56)
                        {
                            if (Chunk[2] == 0x44)
                            {
                                CFI.SetElement("Confirm", ".DVR");
                                CFI.SetElement("Type", "Video");
                                CFI.AddElement("Details", "DVR-Studio Video File");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                //  Genetec video archive  47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x47)
                    {
                        if (Chunk[1] == 0x65)
                        {
                            if (Chunk[2] == 0x6e)
                            {
                                if (Chunk[3] == 0x65)
                                {
                                    if (Chunk[4] == 0x74)
                                    {
                                        if (Chunk[5] == 0x65)
                                        {
                                            if (Chunk[6] == 0x63)
                                            {
                                                if (Chunk[7] == 0x20)
                                                {
                                                    if (Chunk[8] == 0x4f)
                                                    {
                                                        if (Chunk[9] == 0x6d)
                                                        {
                                                            if (Chunk[10] == 0x6e)
                                                            {
                                                                if (Chunk[11] == 0x69)
                                                                {
                                                                    if (Chunk[12] == 0x63)
                                                                    {
                                                                        if (Chunk[13] == 0x61)
                                                                        {
                                                                            if (Chunk[14] == 0x73)
                                                                            {
                                                                                if (Chunk[15] == 0x74)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".G64");
                                                                                    CFI.SetElement("Type", "Video");
                                                                                    CFI.AddElement("Details", "Genetec Video File");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// PEER-TO-PEER

                //  Identify a Torrent file 64 38

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x64)
                    {
                        if (Chunk[1] == 0x38)
                        {
                            CFI.SetElement("Confirm", ".TORRENT");
                            CFI.SetElement("Type", "Torrent");
                            CFI.AddElement("Details", "Bit Torrent File");
                            Identified=true; found=true;
                        }
                    }
                }

// PROGRAMMING

                // Microsoft Developer Studio Project File 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 53 6F 6C 75 74 69 6F 6E 20 46 69 6C 65

                if (ChunkSize > 40 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x69)
                        {
                            if (Chunk[2] == 0x63)
                            {
                                if (Chunk[3] == 0x72)
                                {
                                    if (Chunk[4] == 0x6f)
                                    {
                                        if (Chunk[5] == 0x73)
                                        {
                                            if (Chunk[6] == 0x6f)
                                            {
                                                if (Chunk[7] == 0x66)
                                                {
                                                    if (Chunk[8] == 0x74)
                                                    {
                                                        if (Chunk[9] == 0x20)
                                                        {
                                                            if (Chunk[10] == 0x56)
                                                            {
                                                                if (Chunk[11] == 0x69)
                                                                {
                                                                    if (Chunk[12] == 0x73)
                                                                    {
                                                                        if (Chunk[13] == 0x75)
                                                                        {
                                                                            if (Chunk[14] == 0x61)
                                                                            {
                                                                                if (Chunk[15] == 0x6c)
                                                                                {
                                                                                    if (Chunk[16] == 0x20)
                                                                                    {
                                                                                        if (Chunk[17] == 0x53)
                                                                                        {
                                                                                            if (Chunk[18] == 0x74)
                                                                                            {
                                                                                                if (Chunk[19] == 0x75)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x64)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x69)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x6f)
                                                                                                            {
                                                                                                                if (Chunk[23] == 0x20)
                                                                                                                {
                                                                                                                    if (Chunk[24] == 0x53)
                                                                                                                    {
                                                                                                                        if (Chunk[25] == 0x6f)
                                                                                                                        {
                                                                                                                            if (Chunk[26] == 0x6c)
                                                                                                                            {
                                                                                                                                if (Chunk[27] == 0x75)
                                                                                                                                {

                                                                                                                                    CFI.SetElement("Confirm", ".SLN");
                                                                                                                                    CFI.SetElement("Type", "Programming");
                                                                                                                                    CFI.AddElement("Details", "Microsoft Visual Studio Project File");
                                                                                                                                    Identified=true; found = true;
                                                                                                                                    symboliclinks++;
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Adobe Framemaker File 3C 4D 61 6B 65 72 46 69 6C 65 20

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x3c)
                    {
                        if (Chunk[1] == 0x4d)
                        {
                            if (Chunk[2] == 0x61)
                            {
                                if (Chunk[3] == 0x6b)
                                {
                                    if (Chunk[4] == 0x65)
                                    {
                                        if (Chunk[5] == 0x72)
                                        {
                                            if (Chunk[6] == 0x46)
                                            {
                                                if (Chunk[7] == 0x69)
                                                {
                                                    if (Chunk[8] == 0x6c)
                                                    {
                                                        if (Chunk[9] == 0x65)
                                                        {
                                                            if (Chunk[10] == 0x20)
                                                            {
                                                                CFI.SetElement("Confirm", ".FM");
                                                                CFI.SetElement("Type", "Programming");
                                                                CFI.AddElement("Details", "Adobe Framemaker File");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Visual C PreCompiled header file 56 43 50 43 48 30

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x56)
                    {
                        if (Chunk[1] == 0x43)
                        {
                            if (Chunk[2] == 0x50)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    if (Chunk[4] == 0x48)
                                    {
                                        if (Chunk[5] == 0x30)
                                        {
                                            CFI.SetElement("Confirm", ".PCH");
                                            CFI.SetElement("Type", "Programming");
                                            CFI.AddElement("Details", "Microsoft Visual C Precompiled Header");
                                            Identified=true; found = true;
                                            symboliclinks++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Microsoft Visual Studio C++ Workbench Information File 5B 4D 53 56 43

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x5b)
                    {
                        if (Chunk[1] == 0x4d)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x56)
                                {
                                    if (Chunk[4] == 0x43)
                                    {
                                        CFI.SetElement("Confirm", ".PCH");
                                        CFI.SetElement("Type", "Programming");
                                        CFI.AddElement("Details", "Microsoft Visual Studio Workbench Information File");
                                        Identified=true; found = true;
                                        symboliclinks++;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Microsoft Visual Studio workspace file 64 73 77 66 69 6C 65

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x64)
                    {
                        if (Chunk[1] == 0x73)
                        {
                            if (Chunk[2] == 0x77)
                            {
                                if (Chunk[3] == 0x66)
                                {
                                    if (Chunk[4] == 0x69)
                                    {
                                        if (Chunk[5] == 0x6c)
                                        {
                                            if (Chunk[6] == 0x65)
                                            {
                                                CFI.SetElement("Confirm", ".DSW");
                                                CFI.SetElement("Type", "Programming");
                                                CFI.AddElement("Details", "Microsoft Visual Studio Workspace File");
                                                Identified=true; found = true;
                                                symboliclinks++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// ENGINEERING

                // DTD DesignTools 2D Design File 07 64 74 32 64 64 74 64

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x07)
                    {
                        if (Chunk[1] == 0x64)
                        {
                            if (Chunk[2] == 0x74)
                            {
                                if (Chunk[3] == 0x32)
                                {
                                    if (Chunk[4] == 0x64)
                                    {
                                        if (Chunk[5] == 0x64)
                                        {
                                            if (Chunk[6] == 0x74)
                                            {
                                                if (Chunk[7] == 0x64)
                                                {
                                                    CFI.SetElement("Confirm", ".DTD");
                                                    CFI.SetElement("Type", "Engineering");
                                                    CFI.AddElement("Details", "DTD DesignTools 2D Design File");
                                                    Identified=true; found = true;
                                                    symboliclinks++;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Microsoft Developer Studio Project File 23 20 4D 69 63 72 6F 73 6F 66 74 20 44 65 76 65 6C 6F 70 65 72 20 53 74 75 64 69 6F

                if (ChunkSize > 28 && !found)
                {
                    if (Chunk[0] == 0x23)
                    {
                        if (Chunk[1] == 0x20)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x69)
                                {
                                    if (Chunk[4] == 0x63)
                                    {
                                        if (Chunk[5] == 0x72)
                                        {
                                            if (Chunk[6] == 0x6f)
                                            {
                                                if (Chunk[7] == 0x73)
                                                {
                                                    if (Chunk[8] == 0x6f)
                                                    {
                                                        if (Chunk[9] == 0x66)
                                                        {
                                                            if (Chunk[10] == 0x74)
                                                            {
                                                                if (Chunk[11] == 0x20)
                                                                {
                                                                    if (Chunk[12] == 0x44)
                                                                    {
                                                                        if (Chunk[13] == 0x65)
                                                                        {
                                                                            if (Chunk[14] == 0x76)
                                                                            {
                                                                                if (Chunk[15] == 0x65)
                                                                                {
                                                                                    if (Chunk[16] == 0x6c)
                                                                                    {
                                                                                        if (Chunk[17] == 0x6f)
                                                                                        {
                                                                                            if (Chunk[18] == 0x70) // 65 72 20 53 74 75 64 69 6F
                                                                                            {
                                                                                                if (Chunk[19] == 0x65)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x72)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x20)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x53)
                                                                                                            {
                                                                                                                if (Chunk[23] == 0x74)
                                                                                                                {
                                                                                                                    if (Chunk[24] == 0x75)
                                                                                                                    {
                                                                                                                        if (Chunk[25] == 0x64)
                                                                                                                        {
                                                                                                                            if (Chunk[26] == 0x69)
                                                                                                                            {
                                                                                                                                if (Chunk[27] == 0x6f)
                                                                                                                                {

                                                                                                                                    CFI.SetElement("Confirm", ".DSP");
                                                                                                                                    CFI.SetElement("Type", "Engineering");
                                                                                                                                    CFI.AddElement("Details", "Microsoft Visual Studio Project File");
                                                                                                                                    Identified=true; found = true;
                                                                                                                                    symboliclinks++;
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  MSI Cerius 2 23 20

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x23)
                    {
                        if (Chunk[1] == 0x20)
                        {

                            CFI.SetElement("Confirm", ".MSI");
                            CFI.SetElement("Type", "Engineering");
                            CFI.AddElement("Details", "MSI Cerius 2 File");
                            Identified=true; found = true;
                            symboliclinks++;

                        }
                    }
                }

                // SPSS Data File 24 46 4C 32 40 28 23 29 20 53 50 53 53 20 44 41 54 41 20 46 49 4C 45

                if (ChunkSize > 23 && !found)
                {
                    if (Chunk[0] == 0x24)
                    {
                        if (Chunk[1] == 0x46)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x32)
                                {
                                    if (Chunk[4] == 0x40)
                                    {
                                        if (Chunk[5] == 0x28)
                                        {
                                            if (Chunk[6] == 0x23)
                                            {
                                                if (Chunk[7] == 0x29)
                                                {
                                                    if (Chunk[8] == 0x20)
                                                    {
                                                        if (Chunk[9] == 0x53)
                                                        {
                                                            if (Chunk[10] == 0x50)
                                                            {
                                                                if (Chunk[11] == 0x53)
                                                                {
                                                                    if (Chunk[12] == 0x20)
                                                                    {
                                                                        if (Chunk[13] == 0x44)
                                                                        {
                                                                            if (Chunk[14] == 0x41)
                                                                            {
                                                                                if (Chunk[15] == 0x54)
                                                                                {
                                                                                    if (Chunk[16] == 0x41)
                                                                                    {
                                                                                        if (Chunk[17] == 0x20)
                                                                                        {
                                                                                            if (Chunk[18] == 0x46)  // 46 49 4C 45
                                                                                            {
                                                                                                if (Chunk[19] == 0x49)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x4c)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x45)
                                                                                                        {
                                                                                                            CFI.SetElement("Confirm", ".SAV");
                                                                                                            CFI.SetElement("Type", "Engineering");
                                                                                                            CFI.AddElement("Details", "SPSS Data File");
                                                                                                            Identified=true; found = true;
                                                                                                            symboliclinks++;
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Surfplan kite project file 3A 56 45 52 53 49 4F 4E

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x3a)
                    {
                        if (Chunk[1] == 0x56)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x52)
                                {
                                    if (Chunk[4] == 0x53)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x4f)
                                            {
                                                if (Chunk[7] == 0x4e)
                                                {
                                                    CFI.SetElement("Confirm", ".SLE");
                                                    CFI.SetElement("Type", "Engineering");
                                                    CFI.AddElement("Details", "Surfplan Kite Project File");
                                                    Identified=true; found = true;
                                                    symboliclinks++;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  TCPDump 34 CD B2 A1

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x34)
                    {
                        if (Chunk[1] == 0xcd)
                        {
                            if (Chunk[2] == 0xb2)
                            {
                                if (Chunk[3] == 0xa1)
                                {
                                    CFI.SetElement("Confirm", ".TCPDUMP");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "Libpcap TCPDump File");
                                    Identified=true; found = true;
                                    symboliclinks++;

                                }
                            }
                        }
                    }
                }

                //  Generic AutoCAD Drawing 41 43 31 30

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x43)
                        {
                            if (Chunk[2] == 0x31)
                            {
                                if (Chunk[3] == 0x30)
                                {
                                    CFI.SetElement("Confirm", ".DWG");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "AutoDesk AutoCAD Drawing");
                                    Identified=true; found = true;
                                    symboliclinks++;

                                }
                            }
                        }
                    }
                }

                // Sietronics CPI XRD Document 53 49 45 54 52 4F 4E 49 43 53 20 58 52 44 20 53 43 41 4E

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x53)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x54)
                                {
                                    if (Chunk[4] == 0x52)
                                    {
                                        if (Chunk[5] == 0x4f)
                                        {
                                            if (Chunk[6] == 0x4e)
                                            {
                                                if (Chunk[7] == 0x49)
                                                {
                                                    if (Chunk[8] == 0x43)
                                                    {
                                                        if (Chunk[9] == 0x53)
                                                        {
                                                            if (Chunk[10] == 0x20)
                                                            {
                                                                if (Chunk[11] == 0x58)
                                                                {
                                                                    if (Chunk[12] == 0x52)
                                                                    {
                                                                        if (Chunk[13] == 0x44)
                                                                        {
                                                                            if (Chunk[14] == 0x20)
                                                                            {
                                                                                if (Chunk[15] == 0x53)
                                                                                {
                                                                                    if (Chunk[16] == 0x43)
                                                                                    {
                                                                                        if (Chunk[17] == 0x41)
                                                                                        {
                                                                                            if (Chunk[18] == 0x4e)  // 46 49 4C 45
                                                                                            {
                                                                                                CFI.SetElement("Confirm", ".CPI");
                                                                                                CFI.SetElement("Type", "Engineering");
                                                                                                CFI.AddElement("Details", "Sietronics CPI XRD Document");
                                                                                                Identified=true; found = true;
                                                                                                symboliclinks++;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }



// WINDOWS SPECIFIC

                //  Identify a Microsoft Windows Link file (decimal) 76 0 0 0

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 76)
                    {
                        if (Chunk[1] == 0)
                        {
                            if (Chunk[2] == 0)
                            {
                                if (Chunk[3] == 0)
                                {
                                    CFI.SetElement("Confirm", ".LNK");
                                    CFI.SetElement("Type", "Link");
                                    CFI.AddElement("Details", "Windows Link");
                                    Identified=true; found=true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }

                //  MS Windows Journal File 4E 42 2A 00

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4e)
                    {
                        if (Chunk[1] == 0x42)
                        {
                            if (Chunk[2] == 0x2a)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".JNT");
                                    CFI.SetElement("Type", "Database");
                                    CFI.AddElement("Details", "Windows Journal File");
                                    Identified=true; found = true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }

                //  Windows NT Netmon Capture File 52 54 53 53 

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x54)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    CFI.SetElement("Confirm", ".JNT");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "Windows NT Netmon Capture File");
                                    Identified=true; found = true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }

                //  Windows Program Manager Group File  50 4D 43 43

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x4D)
                        {
                            if (Chunk[2] == 0x43)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                    CFI.SetElement("Confirm", ".GRP");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "Windows Program Manager Group File");
                                    Identified=true; found = true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }

                //  COM+ Catalog File  43 4F 4D 2B

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x2b)
                                {
                                    CFI.SetElement("Confirm", ".CLB");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "Windows COM+ Catalog");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Windows 9x Registry Hive  43 52 45 47

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x47)
                                {
                                    CFI.SetElement("Confirm", "HIVE");
                                    CFI.SetElement("Type", "REGISTRYHIVE");
                                    CFI.AddElement("Details", "Windows 9x Registry Hive File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Skincrafter Skin file 07 53 4b 46

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x07)
                    {
                        if (Chunk[1] == 0x53)
                        {
                            if (Chunk[2] == 0x4b)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".SKF");
                                    CFI.SetElement("Type", "Engineering");
                                    CFI.AddElement("Details", "SkinCrafter Skin File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a REGISTRY HIVE file 72 65 67 66 

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x72)
                    {
                        if (Chunk[1] == 0x65)
                        {
                            if (Chunk[2] == 0x67)
                            {
                                if (Chunk[3] == 0x66)
                                {
                                    CFI.SetElement("Confirm", "HIVE");
                                    CFI.SetElement("Type", "REGISTRYHIVE");
                                    CFI.AddElement("Details", "Microsoft Windows Registry Hive");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                // Regtrans File

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x32)
                    {
                        if (Chunk[2] == 0x33)
                        {
                            if (Chunk[4] == 0x32)
                            {
                                if (Chunk[6] == 0x33)
                                {
                                    CFI.SetElement("Confirm", "REGTRANS-MS");
                                    CFI.SetElement("Type", "REGTRANS-MS");
                                    CFI.AddElement("Details", "Microsoft Windows REGTRANS-MS");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                // WMF Windows Metafile file (win 3.x format) 01 00 09 00 00 03

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x09)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x03)
                                        {
                                            CFI.SetElement("Confirm", ".WMF");
                                            CFI.SetElement("Type", "Metadata");
                                            CFI.AddElement("Details", "Microsoft Windows Metafile");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows NT Registry and Registry Undo files 52 45 47 45 44 49 54

                if (ChunkSize > 7 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x45)
                                {
                                    if (Chunk[4] == 0x44)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x54)
                                            {
                                                CFI.SetElement("Confirm", ".REG");
                                                CFI.SetElement("Type", "Database");
                                                CFI.AddElement("Details", "Microsoft Windows NT Registry or Registry Undo File");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows Dumpfile 4D 44 4D 50 93 A7

                if (ChunkSize > 6 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x50)
                                {
                                    if (Chunk[4] == 0x93)
                                    {
                                        if (Chunk[5] == 0xa7)
                                        {
                                            CFI.SetElement("Confirm", ".DMP");
                                            CFI.SetElement("Type", "DumpFile");
                                            CFI.AddElement("Details", "Microsoft Windows Crash Dump File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows 64-bit memory dump  50 41 47 45 44 55 36 34

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x45)
                                {
                                    if (Chunk[4] == 0x44)
                                    {
                                        if (Chunk[5] == 0x55)
                                        {
                                            if (Chunk[6] == 0x36)
                                            {
                                                if (Chunk[7] == 0x34)
                                                {
                                                    CFI.SetElement("Confirm", "DMP");
                                                    CFI.SetElement("Type", "DumpFile");
                                                    CFI.AddElement("Details", "Microsoft Windows x64 Crash Dump File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows 32-bit memory dump  50 41 47 45 44 55 4D 50

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x50)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x45)
                                {
                                    if (Chunk[4] == 0x44)
                                    {
                                        if (Chunk[5] == 0x55)
                                        {
                                            if (Chunk[6] == 0x4d)
                                            {
                                                if (Chunk[7] == 0x50)
                                                {
                                                    CFI.SetElement("Confirm", "DMP");
                                                    CFI.SetElement("Type", "DumpFile");
                                                    CFI.AddElement("Details", "Microsoft Windows x86 Crash Dump File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // PF Windows Prefetch Data 11 00 00 00 53 43 43 41

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x11)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x53)
                                    {
                                        if (Chunk[5] == 0x43)
                                        {
                                            if (Chunk[6] == 0x43)
                                            {
                                                if (Chunk[7] == 0x41)
                                                {
                                                    CFI.SetElement("Confirm", "PF");
                                                    CFI.SetElement("Type", "Prefetch");
                                                    CFI.AddElement("Details", "Microsoft Windows Prefetch Data");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


                //  INFO2 Recycle Bin 04|05 00 00 00 xx xx xx xx xx xx xx xx 20 03 00 00

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x04 | Chunk[0] == 0x05)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[12] == 0x20)
                                    {
                                        if (Chunk[13] == 0x03)
                                        {
                                            if (Chunk[14] == 0x00)
                                            {
                                                if (Chunk[15] == 0x00)
                                                {
                                                    CFI.SetElement("Confirm", "INFO2");
                                                    CFI.SetElement("Type", "RecycleBin");
                                                    CFI.AddElement("Details", "INFO2 Recycle Bin");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows Event Viewer File 30 00 00 00 4C 66 4C 65

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x30)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x4c)
                                    {
                                        if (Chunk[5] == 0x66)
                                        {
                                            if (Chunk[6] == 0x4c)
                                            {
                                                if (Chunk[7] == 0x65)
                                                {
                                                    CFI.SetElement("Confirm", ".EVT");
                                                    CFI.SetElement("Type", "Log");
                                                    CFI.AddElement("Details", "Microsoft Windows Event File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Windows Event Viewer File 45 6C 66 46 69 6C 65 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x45)
                    {
                        if (Chunk[1] == 0x6c)
                        {
                            if (Chunk[2] == 0x66)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    if (Chunk[4] == 0x69)
                                    {
                                        if (Chunk[5] == 0x6C)
                                        {
                                            if (Chunk[6] == 0x65)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    CFI.SetElement("Confirm", ".EVTX");
                                                    CFI.SetElement("Type", "Log");
                                                    CFI.AddElement("Details", "Microsoft Windows Event File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// EMAIL BOX FORMATS

                //  Identify a Microsoft Windows Personal Folder 21 42 44 4E

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x21)
                    {
                        if (Chunk[1] == 0x42)
                        {
                            if (Chunk[2] == 0x44)
                            {
                                if (Chunk[3] == 0x4E)
                                {
                                    CFI.SetElement("Confirm", ".PST");
                                    CFI.SetElement("Type", "Mailbox");
                                    CFI.AddElement("Details", "Microsoft Windows Personal Folder");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Identify a Microsoft Outlook Folder CF AD 12 FE

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0xCF)
                    {
                        if (Chunk[1] == 0xAD)
                        {
                            if (Chunk[2] == 0x12)
                            {
                                if (Chunk[3] == 0xFE)
                                {
                                    CFI.SetElement("Confirm", ".DBX");
                                    CFI.SetElement("Type", "Mailbox");
                                    CFI.AddElement("Details", "Microsoft Outlook Express DBX File");
                                    Identified = true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Identify a Netscape Commmunicator v4 mail folder 00 1e 84 90 00 00 00 00

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x1e)
                        {
                            if (Chunk[2] == 0x84)
                            {
                                if (Chunk[3] == 0x90)
                                {
                                    if (Chunk[4] == 0x00)
                                    {
                                        if (Chunk[5] == 0x00)
                                        {
                                            if (Chunk[6] == 0x00)
                                            {
                                                if (Chunk[7] == 0x00)
                                                {
                                                    CFI.SetElement("Confirm", ".SNM");
                                                    CFI.SetElement("Type", "Mailbox");
                                                    CFI.AddElement("Details", "Netscape Communicator v4 Mail Folder");
                                                    Identified=true; found=true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Identify a Microsoft Email Message D0 CF 11 E0

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0xD0)
                    {
                        if (Chunk[1] == 0xCF)
                        {
                            if (Chunk[2] == 0x11)
                            {
                                if (Chunk[3] == 0xE0)
                                {
                                    CFI.SetElement("Confirm", ".MSG");
                                    CFI.SetElement("Type", "Mailbox");
                                    CFI.AddElement("Details", "Microsoft Email Message");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  AOL Personal File Cabinet PFC 41 4F 4C 56 4D 31 30 30

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x56)
                                {
                                    if (Chunk[4] == 0x4d)
                                    {
                                        if (Chunk[5] == 0x31)
                                        {
                                            if (Chunk[6] == 0x30)
                                            {
                                                if (Chunk[7] == 0x30)
                                                {
                                                    CFI.SetElement("Confirm", ".PFC");
                                                    CFI.SetElement("Type", "Mailbox");
                                                    CFI.AddElement("Details", "AOL Personal File Cabinet");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  EML

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x46)
                    {
                        if (Chunk[1] == 0x72)
                        {
                            if (Chunk[2] == 0x6f)
                            {
                                if (Chunk[3] == 0x6d)
                                {
                                    if (Chunk[4] == 0x20 || Chunk[4] == 0x3a)
                                    {
                                        if (Chunk[5] == 0x20 || Chunk[5] == 0x3f)
                                        {
                                            CFI.SetElement("Confirm", ".EML");
                                            CFI.SetElement("Type", "Mailbox");
                                            CFI.AddElement("Details", "Email File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Unix Style Mailbox 52 65 74 75 72 6E 2D 50 61 74 68 3A 20

                if (ChunkSize > 13 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x65)
                        {
                            if (Chunk[2] == 0x74)
                            {
                                if (Chunk[3] == 0x75)
                                {
                                    if (Chunk[4] == 0x72)
                                    {
                                        if (Chunk[5] == 0x6e)
                                        {
                                            if (Chunk[6] == 0x2d)
                                            {
                                                if (Chunk[7] == 0x50)
                                                {
                                                    if (Chunk[8] == 0x61)
                                                    {
                                                        if (Chunk[9] == 0x74)
                                                        {
                                                            if (Chunk[10] == 0x68)
                                                            {
                                                                if (Chunk[11] == 0x3a)
                                                                {
                                                                    if (Chunk[12] == 0x20)
                                                                    {
                                                                        CFI.SetElement("Confirm", ".EML");
                                                                        CFI.SetElement("Type", "Mailbox");
                                                                        CFI.AddElement("Details", "Sendmail RFC822 Mailbox");
                                                                        Identified=true; found = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Exchange file extension for emails  58 2D

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x58)
                    {
                        if (Chunk[1] == 0x2d)
                        {
                            CFI.SetElement("Confirm", ".EML");
                            CFI.SetElement("Type", "Mailbox");
                            CFI.AddElement("Details", "Microsoft Exchange Email Box");
                            Identified=true; found = true;
                        }
                    }
                }

// BROWSERS

     // INTERNET EXPLORER

                //  Identify a Microsoft Internet Explorer 8 Cookie 43 6c 69 65 6e 74 20 55 72 6c 43 61 63 68 65 20 4d 4d 46

                if (ChunkSize > 19 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x6c)
                        {
                            if (Chunk[2] == 0x69)
                            {
                                if (Chunk[3] == 0x65)
                                {
                                    if (Chunk[4] == 0x6e)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x20)
                                            {
                                                if (Chunk[7] == 0x55)
                                                {
                                                    if (Chunk[8] == 0x72)
                                                    {
                                                        if (Chunk[9] == 0x6c)
                                                        {
                                                            if (Chunk[10] == 0x43)
                                                            {
                                                                if (Chunk[11] == 0x61)
                                                                {
                                                                    if (Chunk[12] == 0x63)
                                                                    {
                                                                        if (Chunk[13] == 0x68)
                                                                        {
                                                                            if (Chunk[14] == 0x65)
                                                                            {
                                                                                if (Chunk[15] == 0x20)
                                                                                {
                                                                                    if (Chunk[16] == 0x4d)
                                                                                    {
                                                                                        if (Chunk[17] == 0x4d)
                                                                                        {
                                                                                            if (Chunk[18] == 0x46)
                                                                                            {
                                                                                                {
                                                                                                    CFI.SetElement("Confirm", "IE8Cookie");
                                                                                                    CFI.SetElement("Type", "Internet Explorer 8 Cookie Database");
                                                                                                    CFI.AddElement("Details", "Microsoft Internet Explorer 8 Cookie Database");
                                                                                                    Identified=true; found = true;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Microsoft Internet Explorer History File 43 6C 69 65 6E 74 20 55 72 6C 43 61 63 68 65 20 4D 4D 46 20 56 65 72 20

                if (ChunkSize > 25 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x6c)
                        {
                            if (Chunk[2] == 0x69)
                            {
                                if (Chunk[3] == 0x65)
                                {
                                    if (Chunk[4] == 0x6e)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x20)
                                            {
                                                if (Chunk[7] == 0x55)
                                                {
                                                    if (Chunk[8] == 0x72)
                                                    {
                                                        if (Chunk[9] == 0x6c)
                                                        {
                                                            if (Chunk[10] == 0x43)
                                                            {
                                                                if (Chunk[11] == 0x61)
                                                                {
                                                                    if (Chunk[12] == 0x63)
                                                                    {
                                                                        if (Chunk[13] == 0x68)
                                                                        {
                                                                            if (Chunk[14] == 0x65)
                                                                            {
                                                                                if (Chunk[15] == 0x20)
                                                                                {
                                                                                    if (Chunk[16] == 0x4d)
                                                                                    {
                                                                                        if (Chunk[17] == 0x4d)
                                                                                        {
                                                                                            if (Chunk[18] == 0x46) // 20 56 65 72 20
                                                                                            {
                                                                                                if (Chunk[19] == 0x20)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x56)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x65)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x72)
                                                                                                            {
                                                                                                                if (Chunk[23] == 0x20)
                                                                                                                {
                                                                                                                    CFI.SetElement("Confirm", ".DAT");
                                                                                                                    CFI.SetElement("Type", "Database");
                                                                                                                    CFI.AddElement("Details", "Microsoft Internet Explorer History File");
                                                                                                                    Identified=true; found = true;
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

//  CONTACT INFORMATION


                //  ABA Palm Address Book 00 01 42 41

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x42)
                            {
                                if (Chunk[3] == 0x41)
                                {
                                    CFI.SetElement("Confirm", ".ABA");
                                    CFI.SetElement("Type", "Contacts");
                                    CFI.AddElement("Details", "ABA Palm Address Book File");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Skype user data file (profile and contacts) 6C 33 33 6C

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x6c)
                    {
                        if (Chunk[1] == 0x33)
                        {
                            if (Chunk[2] == 0x33)
                            {
                                if (Chunk[3] == 0x6c)
                                {
                                    CFI.SetElement("Confirm", ".DBB");
                                    CFI.SetElement("Type", "Contacts");
                                    CFI.AddElement("Details", "Skype User Data File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                // AOL Feed Bag (Buddy List) 41 4F 4C 20 46 65 65 64 62 61 67

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x20)
                                {
                                    if (Chunk[4] == 0x46)
                                    {
                                        if (Chunk[5] == 0x65)
                                        {
                                            if (Chunk[6] == 0x65)
                                            {
                                                if (Chunk[7] == 0x64)
                                                {
                                                    if (Chunk[8] == 0x62)
                                                    {
                                                        if (Chunk[9] == 0x61)
                                                        {
                                                            if (Chunk[10] == 0x67)
                                                            {
                                                                CFI.SetElement("Confirm", ".BAG");
                                                                CFI.SetElement("Type", "Contacts");
                                                                CFI.AddElement("Details", "AOL Feed Bag / Buddy List");
                                                                Identified=true; found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  AOL Address Book and User Configuration 41 4F 4C 44 42

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x44)
                                {
                                    if (Chunk[4] == 0x42)
                                    {
                                        CFI.SetElement("Confirm", ".ABY");
                                        CFI.SetElement("Type", "Contacts");
                                        CFI.AddElement("Details", "AOL Address Book and User Configuration");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  AOL Address Book Index File 41 4F 4C 49 4E 44 45 58

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x49)
                                {
                                    if (Chunk[4] == 0x4e)
                                    {
                                        if (Chunk[5] == 0x44)
                                        {
                                            if (Chunk[6] == 0x45)
                                            {
                                                if (Chunk[7] == 0x58)
                                                {
                                                    CFI.SetElement("Confirm", ".ABI");
                                                    CFI.SetElement("Type", "Contacts");
                                                    CFI.AddElement("Details", "AOL Address Book Index File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // vCARD file 42 45 47 49 4E 3A 56 43 41 52 44 0D 0A

                if (ChunkSize > 11 && !found)
                {
                    if (Chunk[0] == 0x42)
                    {
                        if (Chunk[1] == 0x45)
                        {
                            if (Chunk[2] == 0x47)
                            {
                                if (Chunk[3] == 0x49)
                                {
                                    if (Chunk[4] == 0x4e)
                                    {
                                        if (Chunk[5] == 0x3a)
                                        {
                                            if (Chunk[6] == 0x56)
                                            {
                                                if (Chunk[7] == 0x43)
                                                {
                                                    if (Chunk[8] == 0x41)
                                                    {
                                                        if (Chunk[9] == 0x52)
                                                        {
                                                            if (Chunk[10] == 0x44)
                                                            {
                                                                if (Chunk[11] == 0x0d)
                                                                {
                                                                    if (Chunk[12] == 0x0a)
                                                                    {
                                                                        CFI.SetElement("Confirm", ".VCF");
                                                                        CFI.SetElement("Type", "Contacts");
                                                                        CFI.AddElement("Details", "vCard Contact Information");
                                                                        Identified=true; found = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }


//  CALENDAR FILES, PROJECTS and SCHEDULES

                //  DBA Palm Datebook Book 00 01 42 44

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x01)
                        {
                            if (Chunk[2] == 0x42)
                            {
                                if (Chunk[3] == 0x41)
                                {
                                    CFI.SetElement("Confirm", ".DBA");
                                    CFI.SetElement("Type", "Calendar");
                                    CFI.AddElement("Details", "DBA Palm Datebook");
                                    Identified=true; found=true;
                                }
                            }
                        }
                    }
                }

                //  Milestone v1 project management and scheduling software 4d 49 4c 45 53

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x45)
                                {
                                    if (Chunk[4] == 0x53)
                                    {

                                        CFI.SetElement("Confirm", ".MLS");
                                        CFI.SetElement("Type", "Project");
                                        CFI.AddElement("Details", "Milestone v1 Project Management File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Milestone v2.1b project management and scheduling software 4D 56 32 31 34

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x56)
                        {
                            if (Chunk[2] == 0x32)
                            {
                                if (Chunk[3] == 0x31)
                                {
                                    if (Chunk[4] == 0x34)
                                    {

                                        CFI.SetElement("Confirm", ".MLS");
                                        CFI.SetElement("Type", "Project");
                                        CFI.AddElement("Details", "Milestone v2.1b Project Management File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  Milestone v2.1c project management and scheduling software 4D 56 32 43

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x56)
                        {
                            if (Chunk[2] == 0x32)
                            {
                                if (Chunk[3] == 0x43)
                                {
                                        CFI.SetElement("Confirm", ".MLS");
                                        CFI.SetElement("Type", "Project");
                                        CFI.AddElement("Details", "Milestone v2.1c Project Management File");
                                        Identified=true; found = true;                  
                                }
                            }
                        }
                    }
                }

// TEXT DOCUMENT IDENTIFICATION

                //  Identify 32 bit Unicode document

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0xFE)
                            {
                                if (Chunk[3] == 0xFF)
                                {
                                    CFI.SetElement("Format", "Unicode-32");
                                    CFI.AddElement("Details", "Unicode-32 Text File");
                                    TextHTML = true;
                                    Executable = false;
                                    Identified=true; found=true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }

                // Unicode extensions 55 43 45 58	

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x55)
                    {
                        if (Chunk[1] == 0x43)
                        {
                            if (Chunk[2] == 0x45)
                            {
                                if (Chunk[3] == 0x58)
                                {
                                    CFI.SetElement("Format", "Unicode");
                                    CFI.AddElement("Details", "Unicode-16 Text File");
                                    TextHTML = true;
                                    Executable = false;
                                    Identified=true; found = true;
                                    symboliclinks++;
                                }
                            }
                        }
                    }
                }


// CD IMAGES
                //  MDF Alcohol 120% CD Image 00 ff ff ff ff ff ff ff ff ff ff 00 00 02 00 01

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0xFF)
                        {
                            if (Chunk[2] == 0xFF)
                            {
                                if (Chunk[3] == 0xFF)
                                {
                                    if (Chunk[4] == 0xFF)
                                    {
                                        if (Chunk[5] == 0xFF)
                                        {
                                            if (Chunk[6] == 0xFF)
                                            {
                                                if (Chunk[7] == 0xFF)
                                                {
                                                    if (Chunk[8] == 0xFF)
                                                    {
                                                        if (Chunk[9] == 0xFF)
                                                        {
                                                            if (Chunk[10] == 0xFF)
                                                            {
                                                                if (Chunk[11] == 0x00)
                                                                {
                                                                    if (Chunk[12] == 0x00)
                                                                    {
                                                                        if (Chunk[13] == 0x02)
                                                                        {
                                                                            if (Chunk[14] == 0x00)
                                                                            {
                                                                                if (Chunk[15] == 0x01)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".MDF");
                                                                                    CFI.SetElement("Type", "CDImage");
                                                                                    CFI.AddElement("Details", "MDF Alcohol 120% Disk Image");
                                                                                    Identified=true; found=true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  NERO CD Compilation 0e 4e 65 72 6f 49 53 4f

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x0E)
                    {
                        if (Chunk[1] == 0x4E)
                        {
                            if (Chunk[2] == 0x65)
                            {
                                if (Chunk[3] == 0x72)
                                {
                                    if (Chunk[4] == 0x6F)
                                    {
                                        if (Chunk[5] == 0x49)
                                        {
                                            if (Chunk[6] == 0x53)
                                            {
                                                if (Chunk[7] == 0x4F)
                                                {
                                                    CFI.SetElement("Confirm", ".NRI");
                                                    CFI.SetElement("Type", "CDImage");
                                                    CFI.AddElement("Details", "NERO CD Complication File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  DAT Runtime Software Disk Image 1A 52 54 53 20 43 4F 4D 50 52 45 53 53 45 44 20 49 4D 41 47 45 20 56 31 2E 30 1A

                if (ChunkSize > 27 && !found)
                {
                    if (Chunk[0] == 0x1A)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x53)
                                {
                                    if (Chunk[4] == 0x20)
                                    {
                                        if (Chunk[5] == 0x43)
                                        {
                                            if (Chunk[6] == 0x4F)
                                            {
                                                if (Chunk[7] == 0x4D)
                                                {
                                                    if (Chunk[8] == 0x50)
                                                    {
                                                        if (Chunk[9] == 0x52)
                                                        {
                                                            if (Chunk[10] == 0x45)
                                                            {
                                                                if (Chunk[11] == 0x53)
                                                                {
                                                                    if (Chunk[12] == 0x53)
                                                                    {
                                                                        if (Chunk[13] == 0x45)
                                                                        {
                                                                            if (Chunk[14] == 0x44)
                                                                            {
                                                                                if (Chunk[15] == 0x20) // 49 4D 41 47 45 20 56 31 2E 30 1A
                                                                                {
                                                                                    if (Chunk[16] == 0x49)
                                                                                    {
                                                                                        if (Chunk[17] == 0x4D)
                                                                                        {
                                                                                            if (Chunk[18] == 0x41)
                                                                                            {
                                                                                                if (Chunk[19] == 0x47)
                                                                                                {
                                                                                                    if (Chunk[20] == 0x45)
                                                                                                    {
                                                                                                        if (Chunk[21] == 0x20)
                                                                                                        {
                                                                                                            if (Chunk[22] == 0x56)
                                                                                                            {
                                                                                                                if (Chunk[23] == 0x31)
                                                                                                                {
                                                                                                                    if (Chunk[24] == 0x2E)
                                                                                                                    {
                                                                                                                        if (Chunk[25] == 0x30)
                                                                                                                        {
                                                                                                                            if (Chunk[26] == 0x1A)
                                                                                                                            {
                                                                                                                                CFI.SetElement("Confirm", ".DAT");
                                                                                                                                CFI.SetElement("Type", "CDImage");
                                                                                                                                CFI.AddElement("Details", "DAT Runtime Software Disk Image");
                                                                                                                                Identified=true; found = true;
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  ISO-9660 43 44 30 30 31

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x30)
                            {
                                if (Chunk[3] == 0x30)
                                {
                                    if (Chunk[4] == 0x31)
                                    {
                                        CFI.SetElement("Confirm", ".ISO");
                                        CFI.SetElement("Type", "CDImage");
                                        CFI.AddElement("Details", "ISO-9660 Disk Image");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  CSO Compressed ISO CD Image 43 49 53 4F

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x4f)
                                {

                                    CFI.SetElement("Confirm", ".CSO");
                                    CFI.SetElement("Type", "CDImage");
                                    CFI.AddElement("Details", "CSO Compressed ISO Disk Image");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  DAX Compress CD Image  44 41 58 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x44)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x58)
                            {
                                if (Chunk[3] == 0x00)
                                {

                                    CFI.SetElement("Confirm", ".DAX");
                                    CFI.SetElement("Type", "CDImage");
                                    CFI.AddElement("Details", "DAX Compressed CD Disk Image");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  VideoVCD 45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x45)
                    {
                        if (Chunk[1] == 0x4e)
                        {
                            if (Chunk[2] == 0x54)
                            {
                                if (Chunk[3] == 0x52)
                                {
                                    if (Chunk[4] == 0x59)
                                    {
                                        if (Chunk[5] == 0x56)
                                        {
                                            if (Chunk[6] == 0x43)
                                            {
                                                if (Chunk[7] == 0x44)
                                                {
                                                    if (Chunk[8] == 0x02)
                                                    {
                                                        if (Chunk[9] == 0x00)
                                                        {
                                                            if (Chunk[10] == 0x00)
                                                            {
                                                                if (Chunk[11] == 0x01)
                                                                {
                                                                    if (Chunk[12] == 0x02)
                                                                    {
                                                                        if (Chunk[13] == 0x00)
                                                                        {
                                                                            if (Chunk[14] == 0x18)
                                                                            {
                                                                                if (Chunk[15] == 0x58)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".VCD");
                                                                                    CFI.SetElement("Type", "CDImage");
                                                                                    CFI.AddElement("Details", "Video VCD Image");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  QEMU Qcow Disk Image  51 46 49 FB

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x51)
                    {
                        if (Chunk[1] == 0x46)
                        {
                            if (Chunk[2] == 0x49)
                            {
                                if (Chunk[3] == 0xFB)
                                {

                                    CFI.SetElement("Confirm", ".IMG");
                                    CFI.SetElement("Type", "CDImage");
                                    CFI.AddElement("Details", "QEMU Qcow Disk Image");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

// DRIVE IMAGES

                //  VMDK Vmware Virtual Disk description file 23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F

                if (ChunkSize > 16 && !found)
                {
                    if (Chunk[0] == 0x23)
                    {
                        if (Chunk[1] == 0x20)
                        {
                            if (Chunk[2] == 0x44)
                            {
                                if (Chunk[3] == 0x69)
                                {
                                    if (Chunk[4] == 0x73)
                                    {
                                        if (Chunk[5] == 0x6b)
                                        {
                                            if (Chunk[6] == 0x20)
                                            {
                                                if (Chunk[7] == 0x44)
                                                {
                                                    if (Chunk[8] == 0x65)
                                                    {
                                                        if (Chunk[9] == 0x73)
                                                        {
                                                            if (Chunk[10] == 0x63)
                                                            {
                                                                if (Chunk[12] == 0x72)
                                                                {
                                                                    if (Chunk[13] == 0x69)
                                                                    {
                                                                        if (Chunk[14] == 0x70)
                                                                        {
                                                                            if (Chunk[15] == 0x74)
                                                                            {
                                                                                if (Chunk[16] == 0x6f)
                                                                                {
                                                                                    CFI.SetElement("Confirm", ".VMDK");
                                                                                    CFI.SetElement("Type", "DriveImage");
                                                                                    CFI.AddElement("Details", "VMWare VMDK Virtual Machine Disk Image");
                                                                                    Identified=true; found = true;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Steganos Security Suite Virual Secure Drive 41 43 76

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x43)
                        {
                            if (Chunk[2] == 0x76)
                            {
                                    CFI.SetElement("Confirm", ".SLE");
                                    CFI.SetElement("Type", "DriveImage");
                                    CFI.AddElement("Details", "Steganos Security Suite Virtual Secure Drive");
                                    Identified=true; found = true;
                            }
                        }
                    }
                }

                //  VMDK 3 Virtual Disk (split) file

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x43)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x57)
                            {
                                if (Chunk[3] == 0x44)
                                {

                                    CFI.SetElement("Confirm", ".VMDK");
                                    CFI.SetElement("Type", "DriveImage");
                                    CFI.AddElement("Details", "VMWare VMDK 3 Virtual Disk File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  VMDK 4 Virtual Disk (split) file

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4b)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                if (Chunk[3] == 0x56)
                                {

                                    CFI.SetElement("Confirm", ".VMDK");
                                    CFI.SetElement("Type", "DriveImage");
                                    CFI.AddElement("Details", "VMWare VMDK 4 Virtual Disk File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  VMDK 4 Virtual Disk (split) file

                if (ChunkSize > 3 && !found)
                {
                    if (Chunk[0] == 0x4b)
                    {
                        if (Chunk[1] == 0x44)
                        {
                            if (Chunk[2] == 0x4d)
                            {
                                CFI.SetElement("Confirm", ".VMDK");
                                CFI.SetElement("Type", "DriveImage");
                                CFI.AddElement("Details", "VMWare VMDK 4 Virtual Disk File");
                                Identified=true; found = true;
                            }
                        }
                    }
                }

                //  Virtual PC Virtual HD Image 63 6F 6E 65 63 74 69 78

                if (ChunkSize > 8 && !found)
                {
                    if (Chunk[0] == 0x63)
                    {
                        if (Chunk[1] == 0x6f)
                        {
                            if (Chunk[2] == 0x6e)
                            {
                                if (Chunk[3] == 0x65)
                                {
                                    if (Chunk[4] == 0x63)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            if (Chunk[6] == 0x69)
                                            {
                                                if (Chunk[7] == 0x78)
                                                {
                                                    CFI.SetElement("Confirm", ".VHD");
                                                    CFI.SetElement("Type", "DriveImage");
                                                    CFI.AddElement("Details", "Microsoft Virtual PC Disk Image File");
                                                    Identified=true; found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// GEOLOCATION

                //  VMapSource GPS Waypoint Database 4D 73 52 63 66

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x73)
                        {
                            if (Chunk[2] == 0x52)
                            {
                                if (Chunk[3] == 0x63)
                                {
                                    if (Chunk[4] == 0x66)
                                    {
                                        CFI.SetElement("Confirm", ".GDB");
                                        CFI.SetElement("Type", "Geolocation");
                                        CFI.AddElement("Details", "VMapSource GPS Waypoint Database");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                //  TomTom Traffic Data File 4E 41 56 54 52 41 46 46 49 43

                if (ChunkSize > 10 && !found)
                {
                    if (Chunk[0] == 0x4e)
                    {
                        if (Chunk[1] == 0x41)
                        {
                            if (Chunk[2] == 0x56)
                            {
                                if (Chunk[3] == 0x54)
                                {
                                    if (Chunk[4] == 0x52)
                                    {
                                        if (Chunk[5] == 0x41)
                                        {
                                            if (Chunk[6] == 0x46)
                                            {
                                                if (Chunk[7] == 0x46)
                                                {
                                                    if (Chunk[8] == 0x49)
                                                    {
                                                        if (Chunk[9] == 0x43)
                                                        {
                                                            CFI.SetElement("Confirm", ".DAT");
                                                            CFI.SetElement("Type", "Geolocation");
                                                            CFI.AddElement("Details", "TomTom Traffic Data File");
                                                            Identified=true; found = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

// MISC (These are often identifications of last resort...)

                // Dial-up Networking File 5B 50 68 6F 6E 65 5D

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x5b)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            if (Chunk[2] == 0x68)
                            {
                                if (Chunk[3] == 0x6f)
                                {
                                    if (Chunk[4] == 0x6e)
                                    {
                                        if (Chunk[5] == 0x65)
                                        {
                                            if (Chunk[6] == 0x5d)
                                            {
                                                CFI.SetElement("Confirm", ".DUN");
                                                CFI.SetElement("Type", "Configuration");
                                                CFI.AddElement("Details", "Dial-Up Networking Configuration File");
                                                Identified=true; found = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  AOL INDEX Preferences File 41 4F 4C 49 44 58

                if (ChunkSize > 7 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x4f)
                        {
                            if (Chunk[2] == 0x4c)
                            {
                                if (Chunk[3] == 0x49)
                                {
                                    if (Chunk[4] == 0x44)
                                    {
                                        if (Chunk[5] == 0x58)
                                        {
                                            CFI.SetElement("Confirm", ".IND");
                                            CFI.SetElement("Type", "Configuration");
                                            CFI.AddElement("Details", "AOL Index Preferences File");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Binary Property Lists 62 70 6C 69 73 74

                if (ChunkSize > 7 && !found)
                {
                    if (Chunk[0] == 0x62)
                    {
                        if (Chunk[1] == 0x70)
                        {
                            if (Chunk[2] == 0x6c)
                            {
                                if (Chunk[3] == 0x69)
                                {
                                    if (Chunk[4] == 0x73)
                                    {
                                        if (Chunk[5] == 0x74)
                                        {
                                            CFI.SetElement("Confirm", ".PLIST");
                                            CFI.SetElement("Type", "Executable");
                                            CFI.AddElement("Details", "Microsoft Binary Property Lists");
                                            Identified=true; found = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //  Flash Cookie 00 BF

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x00)
                    {
                        if (Chunk[1] == 0xBF)
                        {
                            CFI.SetElement("Confirm", ".SOL");
                            CFI.SetElement("Type", "COOKIE");
                            CFI.AddElement("Details", "Adobe Flash Cookie File");
                            Identified=true; found=true;
                        }
                    }
                }

                //  EMF Extended Windows Metafile Format, Printer Spool File

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".EMF");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows Extended Metafile Format Printer Spool File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Winodws NT printer spool file 66 49 00 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x66 || Chunk[0] == 0x67 || Chunk[0] == 0x68)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".SHD");
                                    CFI.SetElement("Type", "Document");
                                    CFI.AddElement("Details", "Microsoft Windows NT Printer Spool File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Intel PROset Wireless Profile 64 00 00 00

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x64)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    CFI.SetElement("Confirm", ".P10");
                                    CFI.SetElement("Type", "Configuration");
                                    CFI.AddElement("Details", "Intel PROset Wireless Profile");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }


                //  RIFF Format (there's many that use this...  They are sorted by the Logical File Adjustments in the Analysis) 52 49 46 46

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x52)
                    {
                        if (Chunk[1] == 0x49)
                        {
                            if (Chunk[2] == 0x46)
                            {
                                if (Chunk[3] == 0x46)
                                {
                                    CFI.SetElement("Confirm", ".RIFF");
                                    CFI.SetElement("Type", "Video");
                                    CFI.AddElement("Details", "RIFF File Format");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  VMWARE BIOS state file 4D 52 56 4E

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x4d)
                    {
                        if (Chunk[1] == 0x52)
                        {
                            if (Chunk[2] == 0x56)
                            {
                                if (Chunk[3] == 0x4e)
                                {
                                    CFI.SetElement("Confirm", ".NVRAM");
                                    CFI.SetElement("Type", "Configuration");
                                    CFI.AddElement("Details", "VMWare BIOS State File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  AOL Parameter and Information Files 41 43 53 44

                if (ChunkSize > 4 && !found)
                {
                    if (Chunk[0] == 0x41)
                    {
                        if (Chunk[1] == 0x43)
                        {
                            if (Chunk[2] == 0x53)
                            {
                                if (Chunk[3] == 0x44)
                                {
                                    CFI.SetElement("Confirm", ".ACSD");
                                    CFI.SetElement("Type", "Configuration");
                                    CFI.AddElement("Details", "AOL Parameter and Information File");
                                    Identified=true; found = true;
                                }
                            }
                        }
                    }
                }

                //  Unidentified PIC file 01 00 00 00 01

                if (ChunkSize > 5 && !found)
                {
                    if (Chunk[0] == 0x01)
                    {
                        if (Chunk[1] == 0x00)
                        {
                            if (Chunk[2] == 0x00)
                            {
                                if (Chunk[3] == 0x00)
                                {
                                    if (Chunk[4] == 0x01)
                                    {
                                        CFI.SetElement("Confirm", ".PIC");
                                        CFI.SetElement("Type", "Picture");
                                        CFI.AddElement("Details", "PIC Image File");
                                        Identified=true; found = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // ARC Archive 1a 02|03|04|08|09

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1a)
                    {
                        if (Chunk[1] == 0x02 || Chunk[1] == 0x03 || Chunk[1] == 0x04 || Chunk[1] == 0x08 || Chunk[1] == 0x09)
                        {
                            CFI.SetElement("Confirm", ".ARC");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "ARC Archive File");
                            Identified=true; found = true;
                        }
                    }
                }

                // PAK Archive 1a 02|03|04|08|09

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x1a)
                    {
                        if (Chunk[1] == 0x0B)
                        {
                            CFI.SetElement("Confirm", ".PAK");
                            CFI.SetElement("Type", "Archive");
                            CFI.AddElement("Details", "PAK Archive File");
                            Identified=true; found = true;
                        }
                    }
                }

                //  Microsoft Document Imaging File

                if (ChunkSize > 2 && !found)
                {
                    if (Chunk[0] == 0x45)
                    {
                        if (Chunk[1] == 0x50)
                        {
                            CFI.SetElement("Confirm", ".MDI");
                            CFI.SetElement("Type", "Document");
                            CFI.AddElement("Details", "Microsoft Document Imaging File");
                            Identified=true; found = true;
                        }
                    }
                }

                CFI.SetElement("Empty", "false");

                if (Executable)
                {
                    CFI.SetElement("Executable", "true");
                }
                else
                {
                    CFI.SetElement("Executable", "false");
                }

                if (asciicheck)
                {
                    if (!found)
                    {
                        CFI.SetElement("Confirm", "Text");
                        CFI.SetElement("Type", "Document");
                        CFI.SetElement("Text", "true");
                        CFI.AddElement("Details", "ASCII/ANSI Text File");
                        Identified=true;
                    }
                    else
                    {
                        CFI.SetElement("Text", "true");
                    }
                }
                else
                {
                    if (ChunkSize > 1 && !found)
                    {
                        if (Chunk[0] == 0xFF)
                        {
                            if (Chunk[1] == 0xFE)
                            {
                                CFI.SetElement("Confirm", ".UTF16");
                                CFI.SetElement("Type", "Document");
                                Identified=true; 
                                found = true;
                                CFI.SetElement("Text", "true");
                                CFI.AddElement("Details", "UTF-16 Text File");
                            }
                        }
                    }

                    if (ChunkSize > 2 && !found)
                    {
                        if (Chunk[0] == 0xEF)
                        {
                            if (Chunk[1] == 0xBB)
                            {
                                if (Chunk[1] == 0xBF)
                                {
                                    CFI.SetElement("Confirm", ".UTF8");
                                    CFI.SetElement("Type", "Document");
                                    Identified=true; found = true;
                                    CFI.SetElement("Text", "true");
                                    CFI.AddElement("Details", "UTF-8 Text File");
                                }
                            }
                        }
                    }
                }
            }

            if (TextHTML)
            {
                CFI.SetElement("Text", "true");
            }

            if (keepCount)
            {                
                if (Identified) identifiedFiles++;
            }

            if (CFI.GetElement("Executable") == "true")
            {
                identifyExecutable(Chunk, ChunkSize, CFI);
            }
        }

        static private Boolean identifyExecutable(byte[] chunk, int chunklen, Tree fileinfo)
        {
            // Is it PE/COFF format?

            Boolean found = false;

            for (int i = 0; i < chunklen - 4; i++)
            {
                if (chunk[i] == 0x50)
                {
                    if (chunk[i] == 0x45)
                    {
                        if (chunk[i] == 0x00)
                        {
                            if (chunk[i] == 0x00)
                            {
                                // This is a PE/COFF Windows file
                                found = true;
                                fileinfo.SetElement("Details", "Microsoft Windows PE/COFF");
                            }
                        }
                    }
                }
            }

            return found;
        }
    }
}
