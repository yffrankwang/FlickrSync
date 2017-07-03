 FlickrSync
=============

Flickr Synchronize Command Line Tool.


 INSTALLATION
---------------

Install dependencies

    pip install --upgrade pytz tzlocal python-dateutil exifread 

On Windows, download and install [pwin32](https://sourceforge.net/projects/pywin32/).

Using git to get source

    git clone https://github.com/pandafw/FlickrSync.git
    
Configure options for file synchronization:

    mkdir ~/the_root_dir_of_flickr
    cp FlickrSync.ini ~/the_root_dir_of_flickr/.flickrsync.ini
    # modify options
    

 RUN
-----

    cd ~/the_root_dir_of_flickr
    python FlickrSync.py sync


 USAGE
-------

    FlickrSync.py <command> ...
      <command>:
        help                print command usage
        get <id>            print remote file info
        tree                list remote albums
          [-?]              exclude file pattern
          [+?]              include file pattern
        sets [cmd]          list remote albums
          [cmd]:
            clear [go]      clear remote albums
            build [go]      build remote albums
        set [cmd] [album]
          [cmd]:
            list            list remote photos of the album
            delete [go]     delete remote album only
            drop   [go]     delete remote album and it's photos
        list                list remote files
          [url]             print remote file URL
          [-?]              exclude file pattern
          [+?]              include file pattern
        scan                scan local files
        pull [go] [force]   download remote files
          [force]           force to update file whose size is different
                            force to trash file that not exists in remote
        push [go] [force]   upload local files
          [force]           force to update file whose size is different
                            force to trash file that not exists in local
        sync [go]           synchronize local <--> remote files
        touch [go]          set local file's modified date by remote
        patch [go]          set remote file's modified date by local
        drop                delete all remote files
    
      <marks>:
        ^-: trash remote file
        ^*: update remote file
        ^+: add remote file
        ^~: patch remote file timestamp
        >*: update local file
        >+: add local file
        >/: add local folder
        >-: trash local file
        >!: remove local file
        >~: touch local file timestamp


 RUNTIME FILES
--------------------
A token file is created during execution:

* `.flickrsync.token`: which has the token to authenticate to Flickr
