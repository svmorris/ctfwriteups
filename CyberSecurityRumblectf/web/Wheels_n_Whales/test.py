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
