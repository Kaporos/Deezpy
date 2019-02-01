# Deezpy - A Deezer track downloader for the commandline
Deezpy is a Deezer track downloader and decrypter, written in Python 3.
It is made to be a minimal and open Deezer downloader, with no obfuscated code. Deezpy is commandline only so it is very lightweight, only around 500 lines of code. And there is still room for improvement.

## Installation
To run the script, you must first download some dependencies. Deezpy is made with as few non-standard libraries as possible in mind. The non-standard libraries needed are `requests`, `cryptography` and `mutagen`.
You can install them with: `pip install requests cryptography mutagen`

After this, you can just download and run the script like any other Python script.

Deezpy generates the download directories and files and a `settings.ini` file in the directory from where you run the script, so it is recommended to run Deezpy inside a new directory. Beyond these, no other config files or temporary files are created.

## Logging in
Deezpy needs to login to Deezer to function properly. Upon the first start, Deezpy promps you to login. It is recommended to make a throwaway account on the Deezer website. Deezpy does not support Facebook or family accounts. Deezpy saves your Deezer password in the settings file as a hex encoded string. **This NOT encryption! Anyone that has access to your `settings.ini` file could decode and retrieve your password.**

## Downloading files
You can choose between two options, download from a single link or batch download links via `downloads.txt`. `downloads.txt` must be in the same directory as `deezpy.py`, with one link per line.

### Download quality
When starting Deezpy for the first time, you can choose the download quality. This setting is saved in `settings.ini`. If the preferred quality is not available for a file, Deezpy will try to download the file in one quality step below your preferred setting. If this quality is also not available it wil download the file one quality step below that and so on.

If you want to change the quality setting, you can edit the `settings.ini` file. The quality settings are as follows:
- "1" = FLAC 1411 kbps
- "2" = MP3 320 kbps
- "3" = MP3 256 kbps
- "4" = MP3 128 kbps

## Download path options
There are many options available for the path specification.
For album tracks:
- Album Artist
- Album
- Year
- Track#
- Disc#
- Title

For playlists:
- Playlist Title
- Track#
- Title

You can modify these to your liking by editing the settings file. The forward slashes indicate a new folder. The default path specifications serve as an example.

## Thank you
Thanks to the author of a script on codegists.com, where I based my script on. That page is now gone, though.
Also thanks to DeezloaderRemix, it served as a great reference, especially for writing the initDeezerApi() function.

## Disclaimer
- We, Deezpy contributors, do not call to commit crimes.
- The usage of this tool may be illegal in your country! Please inform yourself.
- We, Deezpy contributors, do not give any guarantee at all and we are not responsible for damages of all kinds!
