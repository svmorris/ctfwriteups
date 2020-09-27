 <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corona Web</title>
<body>
    

    <style>
        body{
            background-color: whitesmoke
        }
    </style>
<?php

include "flag.php";

echo show_source("index.php");


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

# if useragent =  "020_the_best_year_corona" print flag_1
if ($_SERVER["HTTP_USER_AGENT"] === base64_decode("MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==")){
    echo "<h1 style='color: chartreuse;'>Flag : $flag_1</h1></br>";
}


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



?>
</body>
</html>
