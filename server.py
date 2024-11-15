import configparser
import random
import threading
import time
import logging
import colorlog
from flask import Flask,request,jsonify
import hashlib
config = configparser.ConfigParser()
config.read("serverconf.ini", encoding="UTF-8")

level_str = str(config.get("app","log_level"))


logger = logging.getLogger()
if level_str.upper() == "DEBUG":
    logger.setLevel(logging.DEBUG)
    print("Logger level set to DEBUG")
elif level_str.upper() == "INFO":
    logger.setLevel(logging.INFO)
    print("Logger level set to INFO")
elif level_str.upper() == "WARNING":
    logger.setLevel(logging.WARNING)
    print("Logger level set to WARNING")
elif level_str.upper() == "ERROR":
    logger.setLevel(logging.ERROR)
    print("Logger level set to ERROR")
elif level_str.upper() == "CRITICAL":
    logger.setLevel(logging.CRITICAL)
    print("Logger level set to CRITICAL")
else:
    logger.setLevel("INFO")
time.sleep(1)
logger.setLevel(logging.DEBUG)
handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    fmt='%(log_color)s[%(asctime)s %(funcName)s | %(levelname)-s] -%(reset)s %(message)s',
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

p1 = 0

p1_ofs = 0
p2 = 0

p2_ofs = 0

daytimesec = 0

detfreqsec = 0


nc_its = 0

nc_p1l = 0

nc_p2l = 0
def refreshval():
    global p1,p1_ofs,p2,p2_ofs,daytimesec,detfreqsec,nc_its,nc_p1l,nc_p2l
    p1 = int(config.get("common", "p1"))
    logger.info(f"p1:{p1}")

    p1_ofs = int(config.get("common", "p1_ofs"))
    logger.info(f"p1_ofs:{p1_ofs}")

    p2 = int(config.get("common", "p2"))
    logger.info(f"p2:{p2}")

    p2_ofs = int(config.get("common", "p2_ofs"))
    logger.info(f"p2:{p2_ofs}")

    daytimesec = int(config.get("common", "daytimesec"))
    logger.info(f"daytimesec:{daytimesec}")

    detfreqsec = float(config.get("common", "detfreqsec"))
    logger.info(f"detfreqsec:{detfreqsec}")

    nc_its = int(config.get("nc", "its"))
    logger.info(f"its:{nc_its}")

    nc_p1l = int(config.get("nc", "p1l"))
    logger.info(f"p1l:{nc_p1l}")

    nc_p2l = int(config.get("nc", "p2l"))
    logger.info(f"p2l:{nc_p2l}")




refreshval()
pass
nc_its = int(config.get("nc", "its"))
logger.debug(f"nc_its:{nc_its}")
nc_p1l = int(config.get("nc", "p1l"))
logger.debug(f"nc_p1l:{nc_p1l}")
nc_p2l = int(config.get("nc", "p2l"))
logger.debug(f"nc_p2l:{nc_p2l}")
if (nc_its == 0):
    logger.debug("into its init")
    its = int(time.time())
    print(its)
    config["nc"] = {"its": its, "p1l": nc_p1l, "p2l": nc_p2l}
    with open("serverconf.ini", "w") as conf:
        config.write(conf)

refreshval()

if (nc_p1l == 0 or nc_p2l == 0):
    logger.debug("into pl init")
    p1l = random.randint((p1 - p1_ofs), (p1 + p1_ofs))
    p2l = random.randint((p2 - p2_ofs), (p2 + p2_ofs))
    print(p1l, p2l)
    config["nc"] = {"its": nc_its, "p1l": p1l, "p2l": p2l}
    with open("serverconf.ini", "w") as conf:
        config.write(conf)

refreshval()
loop_its = 0
loop_p1ls = 0
loop_p2ls = 0
il_cid = 0
deltats = 0
timeleft = 0
def loopc():
    global p1,p1_ofs,p2,p2_ofs,daytimesec,detfreqsec,nc_its,nc_p1l,nc_p2l,loop_its,loop_p1ls,loop_p2ls,il_cid,deltats,timeleft
    while True:
        loop_its = nc_its
        loop_p1ls = nc_p1l * daytimesec
        loop_p2ls = nc_p2l * daytimesec
        logger.debug(f"loop_its:{loop_its}, loop_p1ls:{loop_p1ls}, loop_p1ls+loop_p2ls:{loop_p1ls+loop_p2ls}")


        while True:
            time.sleep(detfreqsec)
            deltats = int(time.time() - loop_its)
            logger.debug(deltats)
            if (deltats <= loop_p1ls):
                il_cid = 1
                timeleft = loop_p1ls - deltats
                logger.debug(f"当前周期:{il_cid} 当前deltats:{deltats},距离周期1结束:{timeleft}")

            if(deltats > loop_p1ls and deltats <= loop_p1ls+loop_p2ls):
                il_cid = 2
                timeleft = (loop_p1ls+loop_p2ls) - deltats
                logger.debug(f"当前周期:{il_cid} 当前deltats:{deltats},距离周期2结束:{timeleft}")
            if(deltats >= loop_p2ls+loop_p1ls):
                logger.debug("完成此次循环,重新生成数值并开启下一次循环")
                break
            pass



        its = int(time.time())
        p1l = random.randint((p1 - p1_ofs), (p1 + p1_ofs))
        p2l = random.randint((p2 - p2_ofs), (p2 + p2_ofs))
        config["nc"] = {"its": its, "p1l": p1l, "p2l": p2l}
        with open("serverconf.ini", "w") as conf:
            config.write(conf)

        nc_its = int(config.get("nc", "its"))
        nc_p1l = int(config.get("nc", "p1l"))
        nc_p2l = int(config.get("nc", "p2l"))
logger.info("Starting timer thread")
mainloopcycle = threading.Thread(target=loopc)
mainloopcycle.start()

pwdhash_sd = str(config.get("app","password_sha256")).upper()
logger.info(f"Password hash:{pwdhash_sd}")


def calculate_sha256(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest().upper()

logger.info("Starting web API server")

app = Flask(__name__)
@app.route("/timer/getdata",methods=["GET"])
def timer_getdata():
    password = request.args.get("pwd")
    pwd_hash = calculate_sha256(password)
    if(pwd_hash != pwdhash_sd):
        rd = {
            "message":"FORBIDDEN:Invalid password"
        }
        return rd,403
    rd = {
        "message":"Request processed successfully",
        "data":{
            "current_cycle":il_cid,
            "Remaining_second":timeleft
        }
    }
    return jsonify(rd),200
app.run()
