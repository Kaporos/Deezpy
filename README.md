# Deezpy - A Deezer track downloader for the commandline
Deezpy is a Deezer track downloader and decrypter, written in Python 3.
It is made to be a minimal and open Deezer downloader, with no obfuscated code. Deezpy is commandline only so it is very lightweight, only around 600 lines of code. And there is still room for improvement.

## Installation
To run the script, you must first download some dependencies. Deezpy is made with as few non-standard libraries as possible in mind. The non-standard libraries needed are `requests`, `cryptography` and `mutagen`.
You can install them with: `pip install requests cryptography mutagen`

After this, you can just download and run the script like any other Python script.

Deezpy searches for a `deezpyrc` configuration file in the relevant config folder for your OS. If you have Windows, this is in `%APPDATA%`, for macOs and Linux, this is in `.config`. If it can't find a config file there, it searches the folder from where you run the script from. By default, Deezpy generates the download directories in the directory from where you run the script, so it is recommended to run Deezpy inside a new directory. You can change the downloadpath to a path outside the Deezpy folder by editing `deezpyrc`. Beyond these, no other config files or temporary files are created.

## Logging in
Deezpy needs to login to Deezer to function properly. Upon the first start, Deezpy promps you to give a userToken.

### Instructions to obtain your userToken
The userToken is obtained by logging in to the Deezer website. The next steps can differ per browser.

#### Chrom/ium
1. Press F12
2. Click Application
3. In the left sidebar, click Cookies and then `https://www.deezer.com`
4. In the table, in the row `arl` copy the Value

#### Firefox
1. Press F12
2. Go to storage
3. On the left side click under Cookies click `https://www.deezer.com`
4. In the table, copy the Value of the row with the Name `arl`

## Downloading files
You can choose between three options: download a single link, batch download links via `downloads.txt` or interactive mode, where you can search for tracks, albums or artists.
For batch downloads, `downloads.txt` must be in the same directory as `deezpy.py`, with one link per line.

### Download quality
When starting Deezpy for the first time, you can choose the download quality. This setting is saved in `deezpyrc`. If the preferred quality is not available for a file, Deezpy will try to download the file in one quality step below your preferred setting. If this quality is also not available it wil download the file one quality step below that and so on.

If you want to change the quality setting, you can edit the `deezpyrc` file. The quality settings are as follows:
- "1" = FLAC 1411 kbps
- "2" = MP3 320 kbps
- "3" = MP3 256 kbps
- "4" = MP3 128 kbps

## Download path options
There are many options available for the path specification.
For album tracks:
- Album Artist
- Album
- Date
- Year
- Track#
- Disc#
- Title
- Label
- UPC

For playlists:
- Playlist Title
- Track#
- Title

You can modify these to your liking by editing the settings file. The forward slashes indicate a new folder. The default path specifications serve as an example.

## Thank you
Thanks to the author of a script on codegists.com, where I based my script on. That page is now gone, though.
Special thanks to the team maintaining DeezloaderRemix, without their code Deezpy would not have been here today.

## Disclaimer
- We, Deezpy contributors, do not call to commit crimes.
- The usage of this tool may be illegal in your country! Please inform yourself.
- We, Deezpy contributors, do not give any guarantee at all and we are not responsible for damages of all kinds!
