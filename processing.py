import asyncio
import argparse
import aiomysql
import traceback
import colorlog
from pythonjsonlogger import jsonlogger
import sys
import aiomysql
import configparser
import logging
import zmq
import zmq.asyncio
import struct
import binascii
import aiojsonrpc
from zlib import crc32
import bitcoin

class App():
    def __init__(self, loop, logger, config):
        print("test")
        self.loop = loop
        self.log = logger
        self.zmq_url = config["BITCOIND"]["zeromq"]
        self.zmqContext = zmq.asyncio.Context()
        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.MYSQL_CONFIG = config["MYSQL"]
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashblock")
        # self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashtx")
        # self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawblock")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawtx")
        self.zmqSubSocket.connect(self.zmq_url)
        print(self.zmq_url)
        self.loop.create_task(self.handle())
        # self.loop.create_task(self.rpctest())
        # self.loop.create_task(self.mysqltest())

    async def handle(self) :
        msg = await self.zmqSubSocket.recv_multipart()
        topic = msg[0]
        body = msg[1]
        sequence = "Unknown"
        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)
        if topic == b"hashblock":
            print('- HASH BLOCK ('+sequence+') -')
            print(binascii.hexlify(body))
        elif topic == b"hashtx":
            print('- HASH TX  ('+sequence+') -')
            print(binascii.hexlify(body))
        elif topic == b"rawblock":
            print('- RAW BLOCK HEADER ('+sequence+') -')
            print(binascii.hexlify(body))
        elif topic == b"rawtx":
            self.log.debug("new tx")
            self.loop.create_task(self.handle_tx(body))
            # print('- RAW TX ('+sequence+') -')
            # print(binascii.hexlify(body))
        # schedule ourselves to receive the next message
        asyncio.ensure_future(self.handle())

    async def handle_tx(self, data):
        d = bitcoin.deserialize(data)
        address=list()
        for a in d["outs"]:
            # print(binascii.hexlify(a["script"]))
            # print(bitcoin.script_to_address(binascii.hexlify(a["script"])))
            address.append((bitcoin.script_to_address(binascii.hexlify(a["script"]).decode()),a["value"]))
        print(address)


    async def rpctest(self):
        self.rpc = aiojsonrpc.rpc(self.config["BITCOIND"]["rpc"], loop)
        while 1:
            p = await  self.rpc.getinfo()
            print(p)
            await asyncio.sleep(10)

    async def mysqltest(self):
        conn = await \
            aiomysql.connect(user=self.MYSQL_CONFIG["user"],
                             password=self.MYSQL_CONFIG["password"],
                             db="",
                             host=self.MYSQL_CONFIG["host"],
                             port=int(self.MYSQL_CONFIG["port"]),
                             loop=self.loop)
        cur = await conn.cursor()
        # await init_db(self.MYSQL_CONFIG["database"], cur)
        conn.close()


def init(loop, argv):
    parser = argparse.ArgumentParser(description="Simple processing server  v 0.0.1")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--config", help="config file", type=str, nargs=1, metavar=('PATH',))
    group.add_argument("-l", "--log", help="log file", type=str, nargs=1, metavar=('PATH',))
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="count", default=0)
    parser.add_argument("--json", help="json formatted logs", action='store_true')
    args = parser.parse_args()
    config_file = "simple-processing.cnf"
    log_file = "somple-processing.log"
    log_level = logging.WARNING
    logger = colorlog.getLogger('sp')
    if args.config is not None:
        config_file = args.config
    config = configparser.ConfigParser()
    config.read(config_file)
    if args.log is None:
        if "LOG" in config.sections():
            if "log_file" in config['LOG']:
                log_file = config['LOG']["log_file"]
            if "log_level" in config['LOG']:
                if config['LOG']["log_level"] == "info":
                    log_level = logging.INFO
                elif config['LOG']["log_level"] == "info":
                    log_level = logging.INFO
                elif config['LOG']["log_level"] == "debug":
                    log_level = logging.DEBUG

    else:
        log_file = args.log
    if args.verbose == 0:
        log_level = logging.WARNING
    elif args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose > 1:
        log_level = logging.DEBUG
        if args.verbose > 3:
            connector_debug = True
        if args.verbose > 4:
            connector_debug = True
            connector_debug_full = True
    if log_level == logging.WARNING and "LOG" in config.sections():
        if "log_level" in config['LOG']:
            if config['LOG']["log_level"] == "info":
                log_level = logging.INFO
            elif config['LOG']["log_level"] == "debug":
                log_level = logging.DEBUG

    if args.json:
        logger = logging.getLogger()
        logHandler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter('%(created)s %(asctime)s %(levelname)s %(message)s %(module)s %(lineno)d)')
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)
        logger.setLevel(log_level)
    else:
        logger.setLevel(log_level)
        logger.debug("test")
        fh = logging.FileHandler(log_file)
        fh.setLevel(log_level)
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        formatter = colorlog.ColoredFormatter('%(log_color)s%(asctime)s %(levelname)s: %(message)s (%(module)s:%(lineno)d)')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
    try:
        config["BITCOIND"]["zeromq"]
        config["BITCOIND"]["rpc"]
    except Exception as err:
        print(traceback.format_exc())
        logger.critical("Bitcoind config failed: %s" % err)
        logger.critical("Shutdown")
        sys.exit(0)

    logger.setLevel(log_level)
    logger.info("Start")

    loop = asyncio.get_event_loop()
    app = App(loop, logger, config)
    return app

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop = zmq.asyncio.install()
    app = init(loop, sys.argv[1:])
    loop.run_forever()
    pending = asyncio.Task.all_tasks()
    loop.run_until_complete(asyncio.gather(*pending))
    loop.close()