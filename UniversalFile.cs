using System;

namespace AbsolutionLib.Unraveler
{
    public class UniversalFile
    {
        private string TmpFilename = "";
        public string FullFilename = "";
        public string Filename = "";
        public string Directory = "";
        public Boolean InArchive = false;
        public string ArchiveFullFilename = "";
        public string ArchiveFilename = "";
        public string ArchiveDirectory = "";

        public UniversalFile(string filename)
        {
            TmpFilename = filename;
            
            char[] sep = { '|' };
            char[] sep2 = { '\\' };

            if (!TmpFilename.Contains("|"))
            {
                InArchive = false;
                FullFilename = TmpFilename;
                string[] segments = FullFilename.Split(sep2);

                for (int i = 0; i < segments.Length; i++)
                {
                    if (i == segments.Length - 1)
                    {
                        Filename = segments[i];
                    }
                    else
                    {
                        if (i == 0)
                        {
                            Directory = segments[i];
                        }
                        else
                        {
                            Directory = Directory + "\\" + segments[i];
                        }
                    }
                }
            }
            else
            {
                InArchive = true;
                string[] archivesplit;
                archivesplit = TmpFilename.Split(sep);
                ArchiveFullFilename = archivesplit[0];
                FullFilename = archivesplit[1];

                string[] segments = FullFilename.Split(sep2);

                for (int i = 0; i < segments.Length; i++)
                {
                    if (i == segments.Length - 1)
                    {
                        Filename = segments[i];
                    }
                    else
                    {
                        if (i == 0)
                        {
                            Directory = segments[i];
                        }
                        else
                        {
                            Directory = Directory + "\\" + segments[i];
                        }
                    }
                }

                segments = ArchiveFullFilename.Split(sep2);
                for (int i = 0; i < segments.Length; i++)
                {
                    if (i == segments.Length - 1)
                    {
                        ArchiveFilename = segments[i];
                    }
                    else
                    {
                        if (i == 0)
                        {
                            ArchiveDirectory = segments[i];
                        }
                        else
                        {
                            ArchiveDirectory = ArchiveDirectory + "\\" + segments[i] + "\\";
                        }
                    }
                }
            }
        }

        public string getDirectory()
        {
            return Directory;
        }

        public string getFilename()
        {
            return Filename;
        }

        public string getFullFilename()
        {
            return FullFilename;
        }

        public Boolean isInArchive()
        {
            return InArchive;
        }

        public string getArchiveDirectory()
        {
            return ArchiveDirectory;
        }

        public string getArchiveFilename()
        {
            return ArchiveFilename;
        }

        public string getArchiveFullFilename()
        {
            return ArchiveFullFilename;
        }
    }
}
