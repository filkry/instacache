instacache
==========

Python script to back up clean text and full html versions of Instapaper bookmarks. Tested on ArchLinux, should work on other distros/OSX.

## Requirements

* Python 2.x
* wget (available through every Linux dist package manager, or [homebrew](http://mxcl.github.com/homebrew/) on Mac.
* Instapaper [subscription](http://www.instapaper.com/subscription) for access to full API

## Installation

The recommended method of installation is via pip:

    pip install instacache

This will place instacache.py in your bin folder for easy access.

## Usage
To use Instacache, you need an Instapaper subscription, which gives access to the full developer API as well as a consumer key and secret for OAuth. While I could conceivably ship mine with Instacache as this is an "app", I don't know how to keep that information secret in an open python script.

Create the file `~/.instacache/.credentials` with the following contents:

    [keys]
    consumer_key = <your consumer key>
    consumer_secret = <your consumer secret>

Then you can use the application as follows. After running `instacache.py login` once, you should be fine to run `backup` in a crontab.

    usage: instacache [-h] [-f FILE] {login,user,backup} ...

    Cache Instapaper articles

    optional arguments:
      -h, --help            show this help message and exit
      -f FILE, --file FILE  File in which to store instacache information

    command:
      {login,user,backup}   command to issue
        login               login and create an oauth token
        user                show the currently authed user
        backup              back up instapaper articles

## TODO

Instacache was a pretty quick hack job. There's a lot of things that could be better about it:
* make code cleaner, follow Python naming conventions
* (test and) handle error cases
* allow backup of entire instapaper list in addition to single folder
* remove wget dependency
* migrate to Python 3

These are all "do them if they cause problems" TODOs for me, so if they are causing you problems, create an issue or shoot me an [email](mailto:filipkrynicki@gmail.com).
