import configparser
import random
import time
import logging
import colorlog

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    fmt='%(log_color)s[%(asctime)s | %(levelname)-s] -%(reset)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    log_colors={
        'DEBUG': 'blue',  # 蓝色
        'INFO': 'green',  # 绿色
        'WARNING': 'yellow',  # 黄色
        'ERROR': 'red',  # 红色
        'CRITICAL': 'bold_red',  # 加粗红色
    }

)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.info("Starting Server")
config = configparser.ConfigParser()
config.read("serverconf.ini", encoding="UTF-8")
p1 = 0

p1_ofs = 0
p2 = 0

p2_ofs = 0

daytimesec = 0

detfreqsec = 0


nc_its = 0

nc_p1l = 0

nc_p2l = 0





logger.debug("into pl init")
print(p1 - p1_ofs,p1 + p1_ofs)
print((p2 - p2_ofs), (p2 + p2_ofs))
p1l = random.randint((p1 - p1_ofs), (p1 + p1_ofs))
p2l = random.randint((p2 - p2_ofs), (p2 + p2_ofs))
print(p1l, p2l)
config["nc"] = {"its": nc_its, "p1l": p1l, "p2l": p2l}
logger.info(config)
with open("serverconf.ini", "w") as conf:
    config.write(conf)