#!/usr/bin/env python

# Copyright (C) 2019  Deezpy contributors

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>

# standard libraries:
import configparser
import hashlib
import os
import re
import sys
import platform

# third party libraries:
import mutagen
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


session = requests.Session()
userAgent = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/68.0.3440.106 Safari/537.36'
    )
httpHeaders = {
        'User-Agent'      : userAgent,
        'Content-Language': 'en-US',
        'Cache-Control'   : 'max-age=0',
        'Accept'          : '*/*',
        'Accept-Charset'  : 'utf-8,ISO-8859-1;q=0.7,*;q=0.3',
        'Accept-Language' : 'en-US;q=0.6,en;q=0.4',
        'Connection'      : 'keep-alive',
        }
session.headers.update(httpHeaders)


def apiCall(method, json_req=False):
    ''' Requests info from the hidden api: gw-light.php.
        Used for loginUserToken(), getCSRFToken()
        and privateApi().
    '''
    api_token = 'null' if method == 'deezer.getUserData' else CSRFToken
    unofficialApiQueries = {
        'api_version': '1.0',
        'api_token'  : api_token,
        'input'      : '3',
        'method'     : method
        }
    req = requests_retry_session().post(
        url='https://www.deezer.com/ajax/gw-light.php',
        params=unofficialApiQueries,
        json=json_req
        ).json()
    return req['results']


def loginUserToken(token):
    ''' Handles userToken for deezpyrc file, for initial setup.
        If no USER_ID is found, False is returned and thus the
        cookie arl is wrong. Instructions for obtaining your arl
        string are in the README.md
    '''
    cookies = {'arl': token}
    session.cookies.update(cookies)
    req = apiCall('deezer.getUserData')
    if req['USER']['USER_ID']:
        return True
    else:
        return False


def getCSRFToken():
    ''' A cross-site request forgery token is needed.'''
    req = apiCall('deezer.getUserData')
    global CSRFToken
    CSRFToken = req['checkForm']


def privateApi(songId):
    ''' Get the required info from the unofficial API to decrypt the files.'''
    req = apiCall('deezer.pageTrack', {'SNG_ID': songId})
    privateInfo = req['DATA']
    if "FALLBACK" in privateInfo:
        # Some songs in a playlist have other IDs than the same song
        # in an album/artist page. These ids from songs in a playlist
        # do not return albInfo properly. The FALLBACK id works, however.
        songId = privateInfo["FALLBACK"]['SNG_ID']
        # we need to replace the track with the FALLBACK one
        privateInfo = privateApi(songId)
    return privateInfo


# https://www.peterbe.com/plog/best-practice-with-retries-with-requests
def requests_retry_session(retries=3, backoff_factor=0.3,
                           status_forcelist=(500, 502, 504)):
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=frozenset(['GET', 'POST'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def getJSON(type, id, subtype=""):
    ''' Official API. This function is used to download the ID3 tags.
        Subtype can be 'albums' or 'tracks'.
    '''
    url = f'https://api.deezer.com/{type}/{id}/{subtype}?limit=-1'
    return requests_retry_session().get(url).json()


def getCoverArt(url, filename, size):
    ''' Retrieves the cover art from the official API,
        downloads it to the download folder.
    '''
    url = f'{url}{size}x{size}.png'
    path = os.path.dirname(filename)
    imageFile = path + '/cover' + '.png'
    if not os.path.isdir(path):
        os.makedirs(path)
    if os.path.isfile(imageFile):
        with open(imageFile, 'rb') as f:
            return f.read()
    else:
        with open(imageFile, 'wb') as f:
            r = requests_retry_session().get(url)
            f.write(r.content)
            return r.content


def getLyrics(id, filename):
    ''' Recieves (timestamped) lyrics from the unofficial api
        and converts them to a conventional .lrc file.
        If only the unsynced lyrics are found, these are written
        to a .txt file.
    '''
    req = apiCall('song.getLyrics', {'sng_id': id})
    if 'LYRICS_SYNC_JSON' in req: # synced lyrics
        rawLyrics = req['LYRICS_SYNC_JSON']
        ext = '.lrc'
        lyrics = []
        for lyricLine in rawLyrics:
            try:
                time = lyricLine['lrc_timestamp']
            except KeyError:
                lyricLine = ''
            else:
                line = lyricLine['line']
                lyricLine = time + ' ' + line
            finally:
                lyrics.append(lyricLine + '\n') # TODO add duration?
    elif 'LYRICS_TEXT' in req: # unsynced lyrics
        lyrics = req['LYRICS_TEXT'].splitlines(True) # True keeps the \n
        ext = '.txt'
    else:
        return False
    with open(filename + ext, 'a') as f:
        for lyricLine in lyrics:
            f.write(lyricLine)


def writeTags(filename, ext, trackInfo, albInfo):
    ''' Function to write tags to the file, be it FLAC or MP3.'''
    # retrieve tags
    try:
        genre = albInfo['genres']['data'][0]['name']
    except:
        genre = ''
    tags = {
        'title'       : trackInfo['title'],
        'discnumber'  : trackInfo['disk_number'],
        'tracknumber' : trackInfo['track_position'],
        'album'       : trackInfo['album']['title'],
        'date'        : trackInfo['album']['release_date'],
        'artist'      : trackInfo['artist']['name'],
        'bpm'         : trackInfo['bpm'],
        'albumartist' : albInfo['artist']['name'],
        'totaltracks' : albInfo['nb_tracks'],
        'label'       : albInfo['label'],
        'genre'       : genre
        }
    # Download and load the image
    # cover_xl returns 1000px jpg link, but 1500px png is available, so we modify url
    url = trackInfo['album']['cover_xl'].rsplit('/',1)[0]
    image = getCoverArt(url, filename, 1500)
    if ext == '.flac':
        handle = mutagen.File(filename+ext)
        handle.delete()  # delete pre-existing tags
        if getSetting('embed covers') == 'True':
            pic = mutagen.flac.Picture()
            pic.data = image
            handle.clear_pictures()
            handle.add_picture(pic)

    elif ext == '.mp3':
        handle = MP3(filename+ext, ID3=EasyID3)
        handle.delete()
        # label and albumart are not supported by easyID3, so we add them
        EasyID3.RegisterTextKey("label", "TPUB")
        EasyID3.RegisterTextKey("albumart", "APIC")
        # tracknumber and total tracks is one tag for ID3
        tags['tracknumber'] = (str(tags['tracknumber']) +
                               '/' + str(tags['totaltracks']))
        del tags['totaltracks']
        if getSetting('embed covers') == 'True':
            handle["albumart"] = mutagen.id3.APIC(data=image)
    else:
        print("Could not write tags. File extension not supported.")
        return None

    for key, val in tags.items():
        handle[key] = str(val)
    handle.save()
    return True


# https://gist.github.com/bgusach/a967e0587d6e01e889fd1d776c5f3729
def multireplace(string, replacements):
    ''' Given a string and a replacement map,
        it returns the replaced string.
    '''
    # Sorts the dict so that longer ones first to keep shorter substrings
    # from matching where the longer ones should take place
    substrs = sorted(replacements, key=len, reverse=True)
    # Create a big OR regex that matches any of the substrings to replace
    regexp = re.compile('|'.join(map(re.escape, substrs)))
    # For each match, look up the new string in the replacements
    return regexp.sub(lambda match: replacements[match.group(0)], string)


def nameFile(trackInfo, albInfo, playlistInfo=False):
    ''' Names a file according to a template defined in deezpyrc.'''
    # replacedict is the dictionary to replace pathspec with
    if playlistInfo:
        pathspec = getSetting('playlist naming template')
        replacedict = {
            '<Playlist Title>' : playlistInfo[0]['title'],
            '<Track#>'         : '%d' % playlistInfo[1],
            '<Title>'          : trackInfo['title']
        }
    else:
        pathspec = getSetting('naming template')
        replacedict = {
            '<Album Artist>' : albInfo['artist']['name'],
            '<Album>'        : trackInfo['album']['title'],
            '<Date>'         : trackInfo['album']['release_date'],
            '<Year>'         : trackInfo['album']['release_date'].split('-')[0],
            '<Track#>'       : '%02d' % trackInfo['track_position'],
            '<Disc#>'        : '%d' % trackInfo['disk_number'],
            '<Title>'        : trackInfo['title'],
            '<Label>'        : albInfo['label'],
            '<UPC>'          : albInfo['upc']
        }
    for key, val in replacedict.items():
        # Remove anything that is not an alphanumeric (+non-latin chars),
        # space, dash, underscore, dot or parentheses for every tag:
        val = re.sub(r'(?u)[^-\w.( )]', '', val)
        # folder dirs and the filename are now max 250 bytes long:
        val = val.encode('utf-8')[:250].decode('utf-8', 'ignore')
        replacedict[key] = val
    # replace template with tags
    filename = multireplace(pathspec, replacedict)
    return filename


def getTrackDownloadUrl(privateInfo, quality):
    ''' Calculates the deezer download URL from
        a given MD5_ORIGIN, SNG_ID and MEDIA_VERSION.
        If a user is not logged in, no MD5_ORIGIN is
        found in privateInfo.
    '''
    # this specific unicode char is needed
    char = b'\xa4'.decode('unicode_escape')
    step1 = char.join((privateInfo['MD5_ORIGIN'],
                      quality, privateInfo['SNG_ID'],
                      privateInfo['MEDIA_VERSION']))
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in step1]))
    step2 = m.hexdigest() + char + step1 + char
    step2 = step2.ljust(80, ' ')
    cipher = Cipher(algorithms.AES(bytes('jo6aey6haid2Teih', 'ascii')),
                    modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    step3 = encryptor.update(bytes([ord(x) for x in step2])).hex()
    cdn = privateInfo['MD5_ORIGIN'][0]
    decryptedUrl = 'https://e-cdns-proxy-' + cdn + '.dzcdn.net/mobile/1/' + step3
    return decryptedUrl


def resumeDownload(url, filesize):
    resume_header = {'Range': 'bytes=%d-' % filesize}
    req = requests_retry_session().get(url,
                                       headers=resume_header,
                                       stream=True)
    return req


def deezerTypeId(url):
    ''' Checks if url is valid and then returns type ID.'''
    return url.split('/')[-2:]


def downloadTrack(filename, ext, url, bfKey):
    ''' Download and decrypts a track. Resumes download for tmp files.'''
    if os.path.isfile(filename + '.tmp'):
        print("Resuming download: " + filename + ext + "...")
        filesize = os.stat(filename + '.tmp').st_size  # size downloaded file
        # reduce filesize to a multiple of 2048 for seamless decryption
        filesize = filesize - (filesize % 2048)
        i = filesize/2048
        req = resumeDownload(url, filesize)
    else:
        print("Downloading: " + filename + ext + "...")
        filesize = 0
        i = 0
        req = requests_retry_session().get(url, stream=True)

    # Decrypt content and write to file
    with open(filename + '.tmp', 'ab') as fd:
        fd.seek(filesize)  # jump to end of the file in order to append to it
        # Only every third 2048 byte block is encrypted.
        for chunk in req.iter_content(2048):
            if i % 3 > 0:
                fd.write(chunk)
            elif len(chunk) < 2048:
                fd.write(chunk)
                break
            else:
                cipher = Cipher(algorithms.Blowfish(bfKey),
                                modes.CBC(bytes([i for i in range(8)])),
                                default_backend())
                decryptor = cipher.decryptor()
                decdata = decryptor.update(chunk) + decryptor.finalize()
                fd.write(decdata)
            i += 1
    os.rename(filename + '.tmp', filename + ext)


def getBlowfishKey(id):
    ''' Calculates the Blowfish decrypt key for a given SNG_ID.'''
    secret = 'g4el58wc0zvf9na1'
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in id]))
    idMd5 = m.hexdigest()
    bfKey = bytes(([(ord(idMd5[i]) ^ ord(idMd5[i+16]) ^ ord(secret[i]))
                  for i in range(16)]))
    return bfKey


def getTrack(id, playlist=False):
    ''' Calls the necessary functions to download and tag the tracks.
        Playlist must be a tuple of (playlistInfo, playlistTrack).
    '''
    trackInfo = getJSON('track', id)
    if not trackInfo['readable']:
        print("Song", trackInfo['title'], "not available, skipping...")
        return False
    privateInfo = privateApi(id)
    albInfo = getJSON(*deezerTypeId(trackInfo['album']['link']))
    # if the preferred quality is not available, get the one below etc.
    qualitySetting = int(getSetting("quality")) - 1
    filesize = ['FILESIZE_FLAC', 'FILESIZE_MP3_320','FILESIZE_MP3_256',
                'FILESIZE_MP3_128']#, 'FILESIZE_MP3_64', 'FILESIZE_AAC_64'] TODO add MP3_64 and AAC_64
    qualities = ['9','3','5','1'] #,'',''] # filesize[i] corresponds with qualities[i]
    quality = 0
    for i in range(qualitySetting, len(qualities)-1):
        if int(privateInfo[filesize[i]]) != 0:
            quality = qualities[i]
            break

    if quality == '9':
        ext = '.flac'
    elif quality == '5' or quality == '3' or quality == '1':
        ext = '.mp3'
    else:
        print("Song", trackInfo['title'], "not available, skipping...")
        return False

    if playlist:  # edit some info to get playlist suitable tags
        albInfo['artist']['name'] = 'Various Artists'
        albInfo['nb_tracks'] = playlist[0]['nb_tracks']
        trackInfo['album']['title'] = playlist[0]['title']
        trackInfo['track_position'] = playlist[1]
        trackInfo['disk_number'] = ''
        trackInfo['album']['release_date'] = ''
        trackInfo['album']['cover_xl'] = playlist[0]['picture_xl']
    filename = nameFile(trackInfo, albInfo, playlist)
    if os.path.isfile(filename + ext):
        print(filename + ext, "already exists!")
    else:
        dir = os.path.dirname(filename + ext)
        if not os.path.isdir(dir):
            os.makedirs(dir)
        decryptedUrl = getTrackDownloadUrl(privateInfo, quality)
        bfKey = getBlowfishKey(privateInfo['SNG_ID'])
        downloadTrack(filename, ext, decryptedUrl, bfKey)
        writeTags(filename, ext, trackInfo, albInfo)
        if getSetting('download lyrics') == 'True':
            getLyrics(id, filename)
        print("Done!")


def downloadDeezer(url):
    ''' Extract individual song links from albums and artist pages
        and invokes getTrack(). If it is just a track link,
        only invoke getTrack().
    '''
    if re.fullmatch(r'(http(|s):\/\/)?(www\.)?(deezer\.com\/(.*?)?)'
                    '(playlist|artist|album|track|)\/[0-9]*', url) is None:
        print('"' + url + '": ' + "not a valid link")
        return False
    type, id = deezerTypeId(url)
    if type == 'track':
        getTrack(id)
    # we can't invoke downloadDeezer() again, as in the else block because
    # playlists have a different tracklisting, not available in JSON
    elif type == 'playlist':
        playlistInfo = getJSON(type, id)
        ids = [x["id"] for x in playlistInfo['tracks']['data']]
        playlistTrack = 1
        for id in ids:
            playlist = (playlistInfo, playlistTrack)
            getTrack(id, playlist)
            playlistTrack = playlistTrack + 1
    else:
        subtype = 'albums' if type == 'artist' else 'tracks'
        info = getJSON(type, id)
        if type == 'album':
            print('\n' + info['artist']['name'], '-', info['title'])
        info = getJSON(type, id, subtype)
        urls = [x["link"] for x in info['data']]
        [downloadDeezer(url) for url in urls]


def platformSettingsPath():
    osPlatform = platform.system()
    if osPlatform == 'Linux' or osPlatform == 'Darwin':
       platformPath = os.path.expanduser('~')+'/.config/deezpyrc'
    elif osPlatform == 'Windows':
        platformPath = os.getenv('APPDATA')+'/deezpyrc'
    return platformPath


def checkSettingsFile():
    if os.path.isfile(platformSettingsPath()):
        return platformSettingsPath()
    elif os.path.isfile('deezpyrc'):
        return 'deezpyrc'
    else:
        return None


def getSetting(option, section='DEFAULT'):
    ''' Returns a setting from deezpyrc.'''
    config = configparser.ConfigParser()
    config.read(checkSettingsFile())
    try:
        return config[section][option]
    except KeyError:
        return ''


def setSetting(option,var=False,section='DEFAULT',question=False):
    ''' Adds options to deezpyrc.
        If question: handle simple y/N questions in genSettingsconf().
    '''
    config = configparser.ConfigParser()
    config.read(checkSettingsFile())
    if question:
        while True:
            userOpin = input(question).lower().strip()
            if userOpin == '' or userOpin[0] == 'n':
                var = 'False'
                break
            elif userOpin[0] == 'y':
                var = 'True'
                break
    config.set(section, option, var)
    with open(checkSettingsFile(), 'w') as configfile:
        config.write(configfile)


def genSettingsconf():
    ''' Generates a settings file containing the download path,
        playlist download path, song quality, userToken,
        among other things.
    '''
    print("Settings file not found. Generating the file...")
    pathQuestion = 0
    while 1 > pathQuestion or 2 < pathQuestion:
        try:
            print("\nDo you want to create the settings file in\n1):",
                    platformSettingsPath(),
                   "\n2): In the folder you've ran Deezpy from")
            pathQuestion = int(input("Choice: "))
        except ValueError:
            print("Please enter 1 or 2")
    if pathQuestion == 1:
        settingsPath = platformSettingsPath()
    else:
        settingsPath = 'deezpyrc'

    quality = 0
    while 1 > quality or 4 < quality:
        try:
            print(("\nSelect download quality:"
                   "\n1) Flac 1411 kbps\n2) MP3 320 kbps\n"
                   "3) Mp3 256 kbps\n4) MP3 128 kbps"))
            quality = int(input("Choice: "))
        except ValueError:
            print("Please enter a quality setting\n")

    userToken = input("Deezer userToken: ")
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'naming template'         : 'downloads/<Album Artist>/(<Year>) - <Album>/<Disc#>-<Track#> - <Title>',
        'playlist naming template': 'downloads/playlists/<Playlist Title>/<Track#> - <Title>',
        'quality'                 : quality,
        'userToken'               : userToken
        }
    embedCovers = ("Embed album art to songs? "
                   "This will increase the filesize significantly "
                   "(y/N): ")
    downloadLyrics = "Download lyrics files? (y/N): "
    with open(settingsPath, 'w') as configfile:
        config.write(configfile)
    setSetting('embed album art', question=embedCovers)
    setSetting('download lyrics', question=downloadLyrics)
    print(("If you wish to edit any of these settings, "
           "you can do so in deezpyrc. See the README for more details.\n"))


def batchDownload(queueFile):
    ''' Fetches links from a txt file.'''
    try:
        batchFile = open(queueFile, 'r')
    except OSError as error:
        print(error)
    else:
        links = [line.rstrip() for line in batchFile]
        [downloadDeezer(link) for link in links]


def interactiveMode():
    ''' Launches interactive download mode
        Finds track, album, and artist items
        Performs item discovery through search
        and download from retrieved item urls
    '''
    print("\nSelect download type\n1) Track\n2) Album\n3) Artist")
    itemLut = {
        "1": {
            "selector": "TRACK",
            "string": "{0}) {1} - {2} / {3}",
            "tuple": lambda i, item : (str(i+1), item["SNG_TITLE"], item["ART_NAME"], item["ALB_TITLE"]),
            "type": "song",
            "url": lambda item : "https://www.deezer.com/en/track/" + item["SNG_ID"]
        },
        "2": {
            "selector": "ALBUM",
            "string": "{0}) {1} - {2}",
            "tuple": lambda i, item : (str(i+1), item["ALB_TITLE"], item["ART_NAME"]),
            "type": "album",
            "url": lambda item : "https://www.deezer.com/en/album/" + item["ALB_ID"]
        },
        "3": {
            "selector": "ARTIST",
            "string": "{0}) {1}",
            "tuple": lambda i, item : (str(i+1), item["ART_NAME"]),
            "type": "artist",
            "url": lambda item : "https://www.deezer.com/en/artist/" + item["ART_ID"]
        }
    }
    items = []
    itemType = input("Choice: ")
    if itemType not in [str(n) for n in range(1, 4)]:
        print("Invalid option.")
        return
    maxResults = 10
    searchTerm = input("\nSearch: ")
    if searchTerm == "":
        print("Invalid query.")
        return
    res = apiCall("deezer.suggest", {"NB": maxResults, "QUERY": searchTerm, "TYPES": {
        "ALBUM": True,
        "ARTIST": True,
        "TRACK": True
    }})
    if len(res["TOP_RESULT"]) > 0 and res["TOP_RESULT"][0]["__TYPE__"] == itemLut[itemType]["type"]:
        items += res["TOP_RESULT"]
        if len(res[itemLut[itemType]["selector"]]) > maxResults-1:
            res[itemLut[itemType]["selector"]].pop()
    items += res[itemLut[itemType]["selector"]]
    if len(items) == 0:
        print("No items found.")
        return
    for i in range(len(items)):
        try:
            item = items[i]
            print(itemLut[itemType]["string"].format(*itemLut[itemType]["tuple"](i, item)))
        except:
            continue
    itemChoice = input("Choice: ")
    if itemChoice not in [str(n) for n in range(1, len(items)+1)]:
        print("Invalid option.")
        return
    itemIndex = int(itemChoice)-1
    itemUrl = itemLut[itemType]["url"](items[itemIndex])
    downloadDeezer(itemUrl)


def menu():
    if not checkSettingsFile():
        genSettingsconf()
    bool = loginUserToken(getSetting('userToken'))
    while not bool:
        userToken = input(("Not a valid userToken or the token has expired.\n"
                           "Please enter a new Deezer userToken:"))
        bool = loginUserToken(userToken)
        if bool:
            setSetting('userToken', userToken)
    getCSRFToken()
    while True:
        print(("\nSelect download mode\n1) Single link\n"
               "2) All links (Download all links from downloads.txt,"
               "one link per line)\n3) Interactive"))
        selectDownloadMode = input("Choice: ")

        if selectDownloadMode == '1':
            while True:
                link = input("Download link: ")
                downloadDeezer(link)

        elif selectDownloadMode == '2':
            batchDownload('downloads.txt')

        elif selectDownloadMode == '3':
            interactiveMode()

        else:
            print("Invalid option.\n")

if __name__ == '__main__':
    print(("Thank you for using Deezpy."
           "\nPlease consider supporting the artists!"))
    menu()
