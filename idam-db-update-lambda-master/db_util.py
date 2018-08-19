'''
Created on Aug 10, 2017

@author: 502375911
'''
import logging
import pymysql
import os
from sys import stdout

def setup_logging():
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)

    h = logging.StreamHandler(stdout)

    FORMAT = '%(asctime)s [%(levelname)s] (%(threadName)-10s) %(name)-15s %(message)s'
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

    return logger

logger = setup_logging()

class DBUtil:

    def __init__(self):
        if 'rds_endpoint' in os.environ:
            self.endpoint = os.environ['rds_endpoint']
        if 'rds_user' in os.environ:
            self.user = os.environ['rds_user']
        if 'rds_password' in os.environ:
            self.password = os.environ['rds_password']
        if 'rds_db' in os.environ:
            self.db = os.environ['rds_db']
        if 'rds_port' in os.environ:
            self.port = int(os.environ['rds_port'])
        if 'no_db_ssl' in os.environ:
            self.ssl = False
        else:
            self.ssl = True
        self.connection = self.get_db_connection()

    def get_db_connection(self):
        try:
            connectString = dict(host=self.endpoint,
                             port=self.port,
                             user=self.user,
                             password=self.password,
                             db=self.db,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
            if self.ssl is True:
                connectString['ssl'] = {'ca':'rds-combined-ca-bundle.pem'}
            uom_db_connection = pymysql.connect(**connectString)
            return uom_db_connection
        except Exception as e:
            logger.error("Exception in getUOMDBConnection : " + str(e))
            raise e

    def execute_update(self, sql):
        """Execute update"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql)
                logger.info("rows affected [%s]", cursor.rowcount)
            self.connection.commit()
        except Exception as e:
            logger.error("Exception " + str(e))
            self.connection.rollback()
            raise e


    def execute_query(self, sql, args=None):
        """Execute query"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql, args)
                result = cursor.fetchall()
                logger.debug("result is %s", result)
                logger.info("rows affected [%s]", cursor.rowcount)
                return result
        except Exception as e:
            logger.error("Exception in execute query " + str(e))
            raise e

    def execute_proc(self, sql, args=()):
        """Execute Stored Procedure"""
        try:
            with self.connection.cursor() as cursor:
                res = cursor.callproc(sql, args)
                logger.info(res)
                logger.debug("Stored procedure called successfully")
        except Exception as e:
            logger.error("Exception executing stored procedure " + str(e))
            raise e


    def close_connection(self):
        """Close connection"""
        self.connection.commit()
        self.connection.close()
