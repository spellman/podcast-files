# Manage Podcast Asset Files

* Back-up original recording locally to disk and to Backblaze B2 cloud storage, with `__original` appended to the filename.
    * E.g., `interview-1__original.garageband`
* Back-up final edit to backblaze b2, with timestamp appended to filename.
    * E.g., `interview-1-2024-08-14T10:00:00.000Z.garageband`
* Back-up episode MP3 audio file to backblaze b2
    * E.g., `'Episode 1: It Begins.MP3'`
* Back-up any file
    * E.g., `note.txt`

For back-ups to Backblaze, a file is first zipped and then the zip is uploaded to Backblaze. (This saved ~ 200 MB / file in test
uploads of ~ 1 GB.)

The user's Backblaze API key info, bucket name, and author name are saved in UserDefaults, via the application preferences.
If the data is not found in UserDefaults on application launch and on attempted use, then the application preferences window is shown so the user can provide the data.

Success and failure feedback messages are provided to the user. Retrying on failure is current left to the user. Automatic retrying of applicable failures TBD.



# Used by the Every Mom (Has A Story) podcast:
* https://podcasts.apple.com/fi/podcast/every-mom/id1743895377
* https://open.spotify.com/show/7aXkYnpeHoR7HFYRCeiXHr



#  TODO

1. Display upload progress to the user.
2. Determine which work can really be retried automatically. Automate such retries.
3. Improve spacing in UI.
4. Organize code.
5. Validate preferences and display feedback to the user.
6. Re-enable app sandbox.
