using System;
using System.IO;
using FatumCore;

namespace AbsolutionLib.Unraveler
{
    public class UniversalFileReader
    {
        public string Filename = "";
        int FileType = 0;
        long TotalExtracted = 0;
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
                    TotalExtracted += amountread;
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
                string confirmedtype = identification.getElement("Confirm").ToLower();
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
                identification.dispose();
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
