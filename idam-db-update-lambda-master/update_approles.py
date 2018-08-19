'''
Created on Oct 6, 2017

@author: 502375911
'''
import logging
import sys

def setup_logging():
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    
    h = logging.StreamHandler(sys.stdout)
    
    FORMAT = '%(asctime)s [%(levelname)s] (%(threadName)-10s) %(name)-15s %(message)s'
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)
    
    return logger

logger = setup_logging()

class AppRole:
    
    def __init__(self, dbUtil):
        self.dbutil = dbUtil
        
    def is_event_running(self):
        try:
            response = self.dbutil.execute_query("""
                select count(1) event from INFORMATION_SCHEMA.EVENTS WHERE EVENT_NAME='CALL_ROLE_UPDATE'
            """)
            if response[0]['event'] == 1:
                return True
            else:
                return False
            
        except Exception as e:
            logger.error('Error fetching count [%s]', str(e))
            raise e
            
            
    def __delete_uom_records(self):
        try:
            self.dbutil.execute_query('''
                    delete from uom.user_entity_app_role 
                    where id not in ( select distinct id from uom.user_entity_app_role_baseline )
                    ''');
        except Exception as e:
            logger.error('Error deleting records ' + str(e))
            raise e
    
    def update_roles(self):
        try:
            #res = self.dbutil.execute_proc('update_uom_role_mapping')
            is_running = self.is_event_running()
            if is_running is False:
                self.dbutil.execute_query('''
                    CREATE EVENT CALL_ROLE_UPDATE
                        ON SCHEDULE
                            AT CURRENT_TIMESTAMP
                        DO CALL update_uom_role_mapping()
                ''')
                logger.info('Update Event called')
            else:
                logger.info('Update event is already running')
        except Exception as e:
            logger.error('Error updating roles '+ str(e))
            raise e
        
    def rollback_update(self):
        trunc_er = 'truncate table auth.hc_subject_attribute'
        ins_er = 'insert into auth.hc_subject_attribute select * from auth.hc_subject_attribute_baseline'
        trunc_sa = 'truncate table uom.user_entity_app_role'
        ins_sa = 'insert into uom.user_entity_app_role select * from uom.user_entity_app_role_baseline'
        try:
            logger.debug('Data rollback')
            self.dbutil.execute_query(trunc_er)
            self.dbutil.execute_query(ins_er)
            self.dbutil.execute_query(trunc_sa)
            self.dbutil.execute_query(ins_sa)
            logger.info('Rollback completed')
        except Exception as e:
            logger.error('Error rollback ' + str(e))
            raise e
    