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
    public class UniversalFileReader
    {
        public string Filename = "";
        int FileType = 0;
        BinaryReader infile;
        public string log = "";
        Boolean isOpen = false;
        Tree Config = null;

        public UniStream CurrentStream;
        
        public UniversalFileReader(string filename, Tree config)
        {
            Config = config;
            Filename = filename;
            isOpen = false;
            FileType = identifyFile(filename);
            CurrentStream = new UniStream(filename, FileType, config);
            isOpen = true;
        }

        public UniversalFileReader(UniversalFile UF, Tree config)
        {
            Config = config;
            Filename = UF.ArchiveFullFilename + "|"+UF.Filename;
            isOpen = false;
            FileType = identifyFile(Filename);
            CurrentStream = new UniStream(Filename, FileType, Config);
            isOpen = true;
        }

        public UniversalFileReader(string filename)
        {
            Filename = filename;
            isOpen = false;
            FileType = identifyFile(filename);
            CurrentStream = new UniStream(Filename, FileType, null);
            isOpen = true;
        }

        public int Read(byte[] Buffer, int count)
        {
            int amountread;

            if (isOpen)
            {
                try
                {
                    amountread = CurrentStream.Read(Buffer, count);
                }
                catch (Exception)
                {
                    return -1;
                }
            }
            else
            {
                return -1;
            }
            return amountread;
        }

        public void Close()
        {
            if (isOpen == true)
            {
                if (CurrentStream != null)
                {
                    CurrentStream.Close();
                    CurrentStream = null;
                }

                if (infile != null)
                {
                    infile.Close();
                    infile = null;
                }
            }
            isOpen = false;
        }

        public int identifyFile(string filename)
        {
            int result = 0;

            try
            {
                byte[] BUFFER = new byte[512];
                BinaryReader infile = new BinaryReader(File.OpenRead(Filename));
                int readData = infile.Read(BUFFER, 0, 512);
                Tree identification = FileID.Identify(filename, BUFFER, readData, false);
                string confirmedtype = identification.GetElement("Confirm").ToLower();
                switch (confirmedtype)
                {
                    case ".zip": result = 1; break;
                    case ".gz": result = 2; break;
                    case ".tar": result = 3;  break;
                    //case ".bz2": result = 4; break;
                    case ".7z": result = 5; break;
                    //case ".bz": result = 6; break;
                    //case ".lzh": result = 7; break;
                    case ".rar": result = 8; break;

                    default: FileType = 0; break;
                }
                infile.Close();
                identification.Dispose();
            }
            catch (Exception)
            {

            }
            return result;
        }

        public Boolean findEntry(string filename)
        {
            return CurrentStream.findEntry(filename);
        }

        public Stream OpenEntry()
        {
            return CurrentStream.OpenCurrentEntry();
        }

        public void CloseEntry()
        {
            CurrentStream.CloseCurrentEntry();
        }

        public Tree EntryDetails()
        {
            return CurrentStream.GetDetails();
        }

        private string[] parseFilename(string filename)
        {
            char[] sep = { '|' };
            return Filename.Split(sep);
        }
    }
}
