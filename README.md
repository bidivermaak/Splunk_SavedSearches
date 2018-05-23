Problem Statement:
 
The splunk_ta_windows does a reasonable job of auto-extracting fields in windows security logs.  Unfortunately, many of the auto extracted fields names end up multi-valued and lacking in context due to name collisions of fields within a single event.  The most common example is Account_Name field associated with user logon events.  There are many other highly consequential collisions on field names throughout the windows security log for other EventCodes. 

Mitigation:

To overcome this challenge, I’ve started to curate specialized field extractions for EventCode messages in the windows security log. Eventually I will package this collection of extractions, currently stored in the form of [savedsearches](https://github.com/dstaulcu/Splunk_SavedSearches/blob/master/savedsearches.conf)
, as a Splunk App published to SplunkBase.

![alt tag](https://github.com/dstaulcu/Splunk_SavedSearches/blob/master/screenshot.gif)
