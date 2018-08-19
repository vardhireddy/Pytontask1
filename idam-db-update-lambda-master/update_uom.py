#!/usr/bin/python
'''
Created on Aug 10, 2017

@author: 502375911
'''
import logging
import json
import db_util
from sys import argv
from sys import stdout
from update_approles import AppRole
from db_util import DBUtil

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

def print_defaults(appRole):
    is_running = appRole.is_event_running()
    logger.info('App Role update running status [%s]', is_running)

def app_role_migration(event):
    dbUtil = db_util.DBUtil()
    appRole = AppRole(dbUtil)
    logger.debug(event)
    try:
        isEvent = False if event is None else True
        isRollback = True if (isEvent is True and 'rollback' in event) else False
        isUpdate = True if (isEvent is True and 'update' in event) else False
        logger.debug(isEvent)
        logger.debug(isRollback)
        logger.debug(isUpdate)
        if isEvent is False or (isRollback is False and isUpdate is False) :
            print_defaults(appRole)
        elif isRollback is True and isUpdate is False:
            if event['rollback'] is True:
                logger.info('Rollback the DB updates')
                appRole.rollback_update()
            else:
                print_defaults(appRole)
        elif isUpdate is True and isRollback is False:
            if event['update'] is True:
                logger.debug('in update')
                appRole.update_roles()
            else:
                print_defaults(appRole)
        else:
            logger.debug(event)
            print_defaults(appRole)
    finally:
        dbUtil.close_connection()

def execute_query(appId):
    dbUtil = db_util.DBUtil()

    query1 = """
    select * from uom.application_role
    where application_id=%s
    """

    results = dbUtil.execute_query(query1, appId)

    for result in results:
        logger.info(result)

    query2 = """
    select count(1) users from uom.user_entity_app_role uear
    join uom.application_role ar on uear.app_role_id=ar.id
    where ar.application_id=%s
    """

    result2 = dbUtil.execute_query(query2, appId)

    for result in result2:
        logger.info(result)

    dbUtil.close_connection()

def delete_query(appId):
    dbUtil = db_util.DBUtil()

    query1 = """
    delete uear
    from uom.user_entity_app_role uear
    join uom.application_role ar on uear.app_role_id=ar.id
    where ar.application_id=%s
    """

    query2 = """
    delete from uom.application_role
    where application_id=%s
    """

    query3 = """
    delete from uom.application
    where id=%s
    """

    query4 = """
    delete from uom.entity
    where id=%s
    AND entity_type='APP'
    """

    results = dbUtil.execute_query(query1, appId)

    result2 = dbUtil.execute_query(query2, appId)

    result3 = dbUtil.execute_query(query3, appId)

    result4 = dbUtil.execute_query(query4, appId)

    dbUtil.close_connection()


def delete_ipm_roles(appRole):
    dbUtil = db_util.DBUtil()

    const_app = "APP"
    const_org = "ORG"
    const_site = "SITE"
    const_group = "GROUP"
    const_app_role = "app-role"
    appName = None
    roleCode = None

    appAttributeName = "-".join((const_app, appRole))
    logger.info('App Attribute Name :' + appAttributeName)
    orgAttributeName = "-".join((const_org, appRole))
    logger.info('Org Attribute Name :' + orgAttributeName)
    siteAttributeName = "-".join((const_site, appRole))
    logger.info('Site Attribute Name :' + siteAttributeName)
    groupAttributeName = "-".join((const_group, appRole))
    logger.info('Group Attribute Name :' + groupAttributeName)

    strArray = appRole.split("-")

    if len(strArray) != 0:
        appName = strArray[0]
        roleCode = strArray[1]

        logger.info('App Name :' + appName)
        logger.info('Role Code :' + roleCode)

        deleteUserEntityApplicationRole = """
                delete uear from uom.user_entity_app_role uear
                where uear.app_role_id in (
                    select ar.id from uom.application_role ar
                    where ar.role_code = %s
                    and ar.application_id = (
                        select id from uom.entity ent where ent.entity_type = %s and ent.name = %s
                    )
                )
                """

        deleteGroupEntityApplicationRole = """
                delete gear from uom.group_entity_app_role gear
                where gear.app_role_id in (
                    select ar.id from uom.application_role ar
                    where  ar.role_code = %s
                    and ar.application_id = (
                        select id from uom.entity ent where ent.entity_type = %s and ent.name = %s
                    )
                )
                """

        deleteApplicationRole = """
                delete ar from uom.application_role ar
                where ar.role_code = %s and ar.application_id = (
                    select ent.id from uom.entity ent where ent.entity_type = %s and ent.name = %s
                )
                """

        deleteSubjectAttribute = """
                delete sa from auth.hc_subject_attribute sa
                where sa.attribute_id = (
                    select attr.id from auth.hc_attribute attr where attr.name = %s AND attr.value = %s
                )
                """

        deleteResourceAttribute = """
                delete res from auth.hc_resource res
                where res.attribute_id = (
                    select attr.id from auth.hc_attribute attr where attr.name = %s AND attr.value = %s
                )
                """

        deleteAttribute = """
                delete attr from auth.hc_attribute attr
                where attr.name = %s and attr.value = %s
                """

        logger.info('***UOM Execution Begins***')
        deleteUserEntityApplicationRoleResult = dbUtil.execute_query(deleteUserEntityApplicationRole, [roleCode, const_app, appName])
        logger.info('Deleted Data for User Entity ApplicationRole : ' + appRole)
        deleteGroupEntityApplicationRoleResult = dbUtil.execute_query(deleteGroupEntityApplicationRole, [roleCode, const_app, appName])
        logger.info('Deleted Data for Group Entity ApplicationRole : ' + appRole)
        deleteApplicationRoleResult = dbUtil.execute_query(deleteApplicationRole, [roleCode, const_app, appName])
        logger.info('Deleted Data for ApplicationRole : ' + appRole)
        logger.info('***UOM Execution Ends***')

        logger.info('AUTH Execution Begins for ' + appAttributeName)
        deleteSubjectAttributeResult = dbUtil.execute_query(deleteSubjectAttribute, [const_app_role, appAttributeName])
        logger.info('Deleted Data for Subject Attribute : ' + appAttributeName)
        deleteResourceAttributeResult = dbUtil.execute_query(deleteResourceAttribute, [const_app_role, appAttributeName])
        logger.info('Deleted Data for Resource Attribute : ' + appAttributeName)
        deleteAttributeResult = dbUtil.execute_query(deleteAttribute, [const_app_role, appAttributeName])
        logger.info('Deleted Data for Attribute : ' + appAttributeName)

        logger.info('AUTH Execution Begins for ' + orgAttributeName)
        deleteSubjectAttributeResult = dbUtil.execute_query(deleteSubjectAttribute, [const_app_role, orgAttributeName])
        logger.info('Deleted Data for Subject Attribute : ' + orgAttributeName)
        deleteResourceAttributeResult = dbUtil.execute_query(deleteResourceAttribute, [const_app_role, orgAttributeName])
        logger.info('Deleted Data for Resource Attribute : ' + orgAttributeName)
        deleteAttributeResult = dbUtil.execute_query(deleteAttribute, [const_app_role, orgAttributeName])
        logger.info('Deleted Data for Attribute : ' + orgAttributeName)

        logger.info('AUTH Execution Begins for ' + siteAttributeName)
        deleteSubjectAttributeResult = dbUtil.execute_query(deleteSubjectAttribute, [const_app_role, siteAttributeName])
        logger.info('Deleted Data for Subject Attribute : ' + siteAttributeName)
        deleteResourceAttributeResult = dbUtil.execute_query(deleteResourceAttribute, [const_app_role, siteAttributeName])
        logger.info('Deleted Data for Resource Attribute : ' + siteAttributeName)
        deleteAttributeResult = dbUtil.execute_query(deleteAttribute, [const_app_role, siteAttributeName])
        logger.info('Deleted Data for Attribute : ' + siteAttributeName)

        logger.info('AUTH Execution Begins for ' + groupAttributeName)
        deleteSubjectAttributeResult = dbUtil.execute_query(deleteSubjectAttribute, [const_app_role, groupAttributeName])
        logger.info('Deleted Data for Subject Attribute : ' + groupAttributeName)
        deleteResourceAttributeResult = dbUtil.execute_query(deleteResourceAttribute, [const_app_role, groupAttributeName])
        logger.info('Deleted Data for Resource Attribute : ' + groupAttributeName)
        deleteAttributeResult = dbUtil.execute_query(deleteAttribute, [const_app_role, groupAttributeName])
        logger.info('Deleted Data for Attribute : ' + groupAttributeName)

        logger.info('***AUTH Execution Ends***')

    dbUtil.close_connection()

def delete_user(userId):
    dbUtil = db_util.DBUtil()

    selectUserEntity = """
    select count(1) from uom.user_entity_app_role
    where user_id=%s
    """
    selectUser = """
    select * from uom.user
    where id=%s
    """

    selectUserRegistration = """
    select * from uom.user_registration
    where user_id=%s
    """

    selectUserResult = dbUtil.execute_query(selectUser, userId)
    selectUserEntityResult = dbUtil.execute_query(selectUserEntity, userId)
    selectUserRegistrationResult = dbUtil.execute_query(selectUserRegistration, userId)

    logger.info('User')
    for result in selectUserResult:
        logger.info(result)

    logger.info('User Registration')
    for result in selectUserRegistrationResult:
        logger.info(result)

    logger.info('UserEntityAppRole count')
    for result in selectUserEntityResult:
        logger.info(result)

    deleteUserEntity = """
    delete from uom.user_entity_app_role
    where user_id=%s
    """

    deleteUserReg = """
    delete from uom.user_registration
    where user_id=%s
    """

    deleteUser = """
    delete from uom.user
    where id=%s
    """

    deleteUserEntityResult = dbUtil.execute_query(deleteUserEntity, userId)
    deleteUserRegResult = dbUtil.execute_query(deleteUserReg, userId)
    deleteUserResult = dbUtil.execute_query(deleteUser, userId)

    selectUserResult = dbUtil.execute_query(selectUser, userId)
    selectUserEntityResult = dbUtil.execute_query(selectUserEntity, userId)
    selectUserRegistrationResult = dbUtil.execute_query(selectUserRegistration, userId)

    logger.info('User After delete')
    for result in selectUserResult:
        logger.info(result)

    logger.info('User Registration After delete')
    for result in selectUserRegistrationResult:
        logger.info(result)

    logger.info('UserEntityAppRole count After delete')
    for result in selectUserEntityResult:
        logger.info(result)

    dbUtil.close_connection()

def execute_storedproc():
    dbUtil = db_util.DBUtil()

    query = """
    select * from public.schema_version where version like '18.1%'
    """

    results = dbUtil.execute_query(query);

    for result in results:
        logger.info(result)

    sp = 'public.migrate_groups'
    dbUtil.execute_proc(sp)
    logger.info('Group Mgmt migration complete')

    logger.info('Executing User group role migration...')
    sp_user_group_role = 'public.patch_user_group_roles'
    dbUtil.execute_proc(sp_user_group_role)
    logger.info('User group role migration complete')

    logger.info('Executing addition of HC member role to users...')
    sp_hc_member_role = 'public.patch_hc_member_roles'
    dbUtil.execute_proc(sp_hc_member_role, ['GE-Healthcare', 'GE Health Cloud'])
    logger.info('HC Member role addition complete')

    logger.info('Executing patch group roles...')
    sp_patch_group_role = 'public.patch_group_roles'
    dbUtil.execute_proc(sp_patch_group_role, ['GE-Healthcare', 'GE Health Cloud'])
    logger.info('Patch group roles complete')

    dbUtil.close_connection()

def add_ge_admin_to_org(userId, orgId, roleName):
    dbUtil = db_util.DBUtil()

    query = """
    insert into uom.user_entity_role
    (id, entity_id, role_id, user_id)
    select
        uuid(),'""" + orgId + """',
        r.id role_id,'""" + userId + """'
    from
        uom.role r
        where
        r.name = '""" + roleName + """'
    """
    dbUtil.execute_query(query, None)
    logger.info('Execution complete')
    dbUtil.close_connection()

def update_entity_name(entityId,entityName):
    dbUtil = db_util.DBUtil()

    query1 = """
    select * from uom.entity
    where id=%s
    """
    logger.info('Fetching details for entity '+entityId)
    results = dbUtil.execute_query(query1, entityId)

    for result in results:
        logger.info(result)

    query2 = """
    update uom.entity
    set name=%s
    where
    id=%s
    """

    result2 = dbUtil.execute_query(query2, [entityName, entityId])

    for result in result2:
        logger.info(result)

    logger.info('Fetching details for entity after update '+entityId)
    results = dbUtil.execute_query(query1, entityId)

    for result in results:
        logger.info(result)

    dbUtil.close_connection()

def update_grp_membership(orgId):
    dbUtil = db_util.DBUtil()

    select_query = """
    select * from uom.group
    where org_id=%s
    and membership='EXTERNAL'
    """

    results = dbUtil.execute_query(select_query, orgId)

    logger.info('External groups for org [%s] before update', orgId )

    for result in results:
        logger.info(result)

    update_query = """
    UPDATE uom.group
    SET membership='INTERNAL'
    WHERE
    membership='EXTERNAL'
    AND
    org_id=%s
    """

    results2 = dbUtil.execute_query(update_query, orgId)

    logger.info('External groups update query for ORG [%s]', orgId )

    for result in results2:
        logger.info(result)

    results = dbUtil.execute_query(select_query, orgId)

    logger.info('External groups for org [%s] after update', orgId )

    for result in results:
        logger.info(result)

    dbUtil.close_connection()

def check_version():
    dbUtil = db_util.DBUtil()

    query = """
    select * from public.schema_version
    """

    results = dbUtil.execute_query(query);

    for result in results:
        logger.info(result)

    logger.info('*******************************************')

    query1 = """
    select * from information_schema.tables
    where table_schema in ('uom', 'auth')
    """

    results2 = dbUtil.execute_query(query1);

    for result in results2:
        logger.info(result)

    dbUtil.close_connection()

def check_application_roles():
    dbUtil = db_util.DBUtil()

    query = """
    select * from uom.application_role
    """

    results = dbUtil.execute_query(query);

    for result in results:
        logger.info(result)

    dbUtil.close_connection()

def check_application_roles_user(userId):
    dbUtil = db_util.DBUtil()

    query1 = """
    select
        u.user_name username,
        ae.entity_type role_entity,
        ae.name role_application,
        ar.role_code role_code,
        e.entity_type entity_type,
        e.name entity_name,
        oe.name parent_organization,
        ge.name group_name
    from
    uom.user_entity_app_role uear
        join uom.user u on uear.user_id = u.id
        join uom.entity e on uear.entity_id = e.id
        join uom.application_role ar on uear.app_role_id = ar.id
            join uom.application a on ar.application_id = a.id
            join uom.entity ae on a.id = ae.id
        join uom.organization o on uear.org_id=o.id
            join uom.entity oe on oe.id = o.id
        left join uom.group g on uear.parent_group_id = g.id
            left join uom.group_attributes ga on g.id = ga.group_id
            left join uom.entity ge on g.id = ge.id
    where
        uear.user_id=%s
    """

    results2 = dbUtil.execute_query(query1, userId);

    for result in results2:
        logger.info(result)

    dbUtil.close_connection()



def select_proxexec_status():
    dbUtil = db_util.DBUtil()

    query1 = """
    select * from public.stor_proc_exec_status
    """

    results2 = dbUtil.execute_query(query1)

    for result in results2:
        logger.info(result)

    dbUtil.close_connection()

def update_proxexec_status(procName):
    dbUtil = db_util.DBUtil()

    query1 = """
    update public.stor_proc_exec_status
    set status=0
    where proc_name = %s
    """

    results2 = dbUtil.execute_query(query1, procName)

    for result in results2:
        logger.info(result)

    dbUtil.close_connection()

def fix_auth_db(query):
    dbUtil = db_util.DBUtil()



    logger.info('Begin execution data sync')

    dbUtil.execute_query(query)

    logger.info('End execution data sync')

    dbUtil.close_connection()


def update_app_Role(roleId, role_display_name):
    dbUtil = db_util.DBUtil()

    query = """
    UPDATE  uom.application_role SET role_display_name = '"""+role_display_name+"""' WHERE id = '"""+roleId+"""'
    """

    dbUtil.execute_query(query, None)
    logger.info('Execution complete')
    dbUtil.close_connection()

def disable_patient_role_for_user(emailId, patient_role_id):
    dbUtil = db_util.DBUtil()

    query = """
    DELETE FROM uom.user_entity_app_role WHERE user_id in (SELECT id FROM uom.user WHERE email ='"""+emailId+"""' ) and app_role_id= '"""+patient_role_id+"""'
    """

    dbUtil.execute_query(query, None)
    logger.info('Execution complete')
    dbUtil.close_connection()


def get_api_for_user(user_name):
    dbUtil = db_util.DBUtil()
    output=[]

    query = """
     select auth.hc_attribute.value, auth.hc_attribute.name from auth.hc_attribute where auth.hc_attribute.id in
     (select auth.hc_subject_attribute.attribute_id from auth.hc_subject_attribute where auth.hc_subject_attribute.subject_id in
     (select auth.hc_subject.id from auth.hc_subject where auth.hc_subject.user_name='"""+user_name+"""'))
     """
    results = dbUtil.execute_query(query)
    for result in results:
        output.append(result)
    logger.info(output)

    logger.info('Execution complete')
    dbUtil.close_connection()

def get_old_orgs():
    dbUtil = db_util.DBUtil()
    output= []
    query = """
    SELECT uom.organization.name, uom.organization.nick_name, uom.organization.created_date FROM uom.organization
    order by uom.organization.created_date limit 20;
    """

    results = dbUtil.execute_query(query);
    logger.info("Organizations by date: ")

    for result in results:
        output.append(result)
    logger.info(output)

    dbUtil.close_connection()

def get_sites_for_orgs(orgId):
    dbUtil = db_util.DBUtil()
    output= []
    query = """
    SELECT * FROM uom.site where uom.site.organization_id= '"""+orgId+"""'
    """

    results = dbUtil.execute_query(query);
    logger.info("sites for this org are: ")

    for result in results:
        output.append(result)
    logger.info(output)

    dbUtil.close_connection()

def migrate_site_user_roles_authDB(user_id):
    dbUtil = db_util.DBUtil()
    attributeIds = []

    query1 = """
    select auth.hc_subject.id from auth.hc_subject where auth.hc_subject.user_id = '"""+user_id+"""'
    """
    query1_output = dbUtil.execute_query(query1)
    logger.info('query 1 output: [%s] ', query1_output)

    subject_id = query1_output[0]['id']
    logger.info('subject_id is : [%s]', subject_id)

    delete_org_roles_if_any_for_user_query = """delete from auth.hc_subject_attribute where auth.hc_subject_attribute.subject_id='"""+subject_id+"""' and
     auth.hc_subject_attribute.attribute_id in
     (select auth.hc_attribute.id from auth.hc_attribute where  auth.hc_attribute.value LIKE 'ORG-%')"""

    query_output = dbUtil.execute_update(delete_org_roles_if_any_for_user_query)
    logger.info('Deletion done')


    get_attributeId_from_subjId = """
    select auth.hc_subject_attribute.attribute_id from auth.hc_subject_attribute where auth.hc_subject_attribute.subject_id = '"""+subject_id+"""'
    """
    query2_output = dbUtil.execute_query(get_attributeId_from_subjId)

    for result in query2_output:
        attributeIds.append(result['attribute_id'])

    logger.info('query 2 output: [%s]', attributeIds)

    for attribute_id in attributeIds:
        logger.info('attribute_id is::[%s] ', attribute_id)

        get_site_role = """SELECT auth.hc_attribute.value FROM auth.hc_attribute where id =  '"""+attribute_id+"""'"""
        get_site_role_query = dbUtil.execute_query(get_site_role)
        logger.info('site role value is:: [%s] ', get_site_role_query)
        site_role_value = get_site_role_query[0]['value']
        logger.info('site role value is:: [%s] ', site_role_value)


        get_org_role_value_from_site_role_value="""
          SELECT REPLACE('"""+site_role_value+"""', 'SITE-','ORG-')
           """
        get_org_role_value_from_site_role_value_query = dbUtil.execute_query(get_org_role_value_from_site_role_value)
        logger.info('org role value is:: [%s] ', get_org_role_value_from_site_role_value_query)
        logger.info('org role value is:: [%s] ', list(get_org_role_value_from_site_role_value_query[0].values())[0])

        org_role_attributeId= """SELECT auth.hc_attribute.id from auth.hc_attribute where auth.hc_attribute.value= '"""+list(get_org_role_value_from_site_role_value_query[0].values())[0]+"""'"""
        query_org_role_attributeId = dbUtil.execute_query(org_role_attributeId)
        logger.info('org attribute_id is:: [%s] ', query_org_role_attributeId[0]['id'])
	
	
        query3 = """UPDATE auth.hc_subject_attribute set auth.hc_subject_attribute.attribute_id = '"""+query_org_role_attributeId[0]['id']+"""'
                 where auth.hc_subject_attribute.subject_id= '"""+subject_id+"""' and auth.hc_subject_attribute.attribute_id = '"""+attribute_id+"""'"""

        # query3= """
	    #          update auth.hc_subject_attribute set auth.hc_subject_attribute.attribute_id =
	    #         (select auth.hc_attribute.id from auth.hc_attribute
	    #          where auth.hc_attribute.value in
	    #        (select REPLACE((SELECT auth.hc_attribute.value FROM auth.hc_attribute where id = '"""+attribute_id+"""') , 'SITE-','ORG-')))
	    #         where auth.hc_subject_attribute.subject_id= '"""+subject_id+"""' and auth.hc_subject_attribute.attribute_id = '"""+attribute_id+"""'
        # "

        query3_output = dbUtil.execute_update(query3)
        logger.info('Done updating for att id [%s] ', attribute_id)
	
    logger.info('Execution complete')
    dbUtil.close_connection()


def migrate_user_site_to_org_in_uomDB(userId, oldOrgId, siteId, newOrgId):
    dbUtil = db_util.DBUtil()
    logger.info('Migrating uomDb data')

    querySetForeignKey0 = """
        SET foreign_key_checks = 0;
    """
    dbUtil.execute_query(querySetForeignKey0)

    queryUpdateEAR = """
        UPDATE uom.user_entity_app_role SET entity_id='""" + newOrgId + """', org_id='""" + newOrgId + """'
        WHERE entity_id='""" + siteId + """' AND org_id='""" + oldOrgId + """' AND user_id= '""" + userId + """' ;
    """
    dbUtil.execute_update(queryUpdateEAR)

    querySetForeignKey1 = """
        SET foreign_key_checks = 1;
    """
    dbUtil.execute_query(querySetForeignKey1)

    queryDeleteEAR = """
        DELETE from uom.user_entity_app_role WHERE org_id='""" + oldOrgId + """' AND entity_id='""" + oldOrgId + """' AND user_id='""" + userId + """';
    """
    dbUtil.execute_update(queryDeleteEAR)
    
    queryDeleteEAS = """
            DELETE from uom.user_entity_applicationservice WHERE user_id='""" + userId + """';
        """
    dbUtil.execute_update(queryDeleteEAS)

def site_to_org_migration(emailID_list, oldOrgId, siteId, newOrgId):
    dbUtil = db_util.DBUtil()

    logger.info("Old Organization Id: [%s] " + oldOrgId)
    logger.info("New Organization Id: [%s] " + newOrgId)
    logger.info("Site Id: [%s] " + siteId)

    userIdList = []

    
    for eachEmail in emailID_list:
        entity_id_list = []
        queryGetUserID = """
                     SELECT id FROM uom.user where email = '""" + eachEmail + """';
                 """
        queryGetUserIDResult = dbUtil.execute_query(queryGetUserID)
        logger.info("queryGetUserIDResult [%s]", queryGetUserIDResult[0]['id'])
    
        queryUserSiteFiltering = """
                     SELECT entity_id FROM uom.user_entity_app_role where user_id = '""" + queryGetUserIDResult[0]['id'] + """';
                 """
        query_entity_id_list = dbUtil.execute_query(queryUserSiteFiltering)
    
        logger.info("query_entity_id_list [%s] ", query_entity_id_list)
    
        for each_entity_id_list_result in query_entity_id_list:
            entity_id_list.append(each_entity_id_list_result['entity_id'])
    
        if siteId in entity_id_list:
            userIdList.append(queryGetUserIDResult[0]['id'])
    
    logger.info(userIdList)
    
    for userId in userIdList:
        logger.info('Migrating userID [%s] ' + userId)
        migrate_user_site_to_org_in_uomDB(userId, oldOrgId, siteId, newOrgId)
        migrate_site_user_roles_authDB(userId)
    
    queryDeleteEARForSuperAdmin = """
                   DELETE from uom.user_entity_app_role WHERE org_id='""" + oldOrgId + """' AND entity_id='""" + siteId + """';
               """
    dbUtil.execute_update(queryDeleteEARForSuperAdmin)
    
    queryDeleteOrg = """
            DELETE from uom.site WHERE organization_id='""" + oldOrgId + """' AND id ='""" + siteId + """';
         """
    
    dbUtil.execute_update(queryDeleteOrg)
    
    logger.info('Execution complete')
    dbUtil.close_connection()
    
def test_migrate_user_site_to_org_in_uomDB(userId, oldOrgId, siteId, newOrgId):
    dbUtil = db_util.DBUtil()

    testQueryGetUserOrg = """
           select distinct entity_id from uom.user_entity_app_role where user_id = '""" + userId + """' ;
       """
    query_entity_id_list = dbUtil.execute_query(testQueryGetUserOrg)

    logger.info("query_entity_id_list [%s] ", query_entity_id_list)
    entity_id_list = []

    for each_entity_id_list_result in query_entity_id_list:
        entity_id_list.append(each_entity_id_list_result['entity_id'])

    if oldOrgId not in entity_id_list and siteId not in entity_id_list and newOrgId in entity_id_list:
        logger.info("User with Successfully migrated. [%s] " + userId)
    else:
        logger.info("Error in migrating user - [%s] " + userId)

    logger.info("Done with test_migrate_user_site_to_org_in_uomDB for [%s] ", userId)
    dbUtil.close_connection()


def test_migrate_site_user_roles_authDB(userId):
    dbUtil = db_util.DBUtil()

    query1 = """
    select auth.hc_subject.id from auth.hc_subject where auth.hc_subject.user_id = '""" + userId + """'
    """
    query1_output = dbUtil.execute_query(query1)
    subject_id = query1_output[0]['id']
    logger.info('subject_id is : [%s] ', subject_id)

    query_get_roles_count = """
    SELECT count(value) FROM auth.hc_attribute where value like 'SITE-%' AND id in (SELECT attribute_id from auth.hc_subject_attribute where subject_id = '""" + subject_id + """"' )

    """
    get_roles_count = dbUtil.execute_query(query_get_roles_count)

    logger.info("get_roles_count [%s] ", get_roles_count)

    if get_roles_count[0]['count(value)'] == 0:
        logger.info('Roles transferred Successfully')
    else:
        logger.info("Error in migrating user- [%s] ", userId)
    logger.info("Done with test_migrate_site_user_roles_authDB for [%s]", userId)

    dbUtil.close_connection()

def test_delete_user_app_services_uomDB(userId):
    dbUtil = db_util.DBUtil()
    queryDeleteAppServices = """
    	DELETE from uom.user_entity_applicationservice where user_id = '""" + userId + """'
    """
    dbUtil.execute_update(queryDeleteAppServices)
    
    logger.info('App services Deletion complete ')
    dbUtil.close_connection()

def test_site_to_org_migration(emailID_list, oldOrgId, siteId, newOrgId):
    dbUtil = db_util.DBUtil()

    logger.info("Old Organization Id: [%s] " + oldOrgId)
    logger.info("New Organization Id: [%s] " + newOrgId)
    logger.info("Site Id: [%s] " + siteId)
    
    for eachEmail in emailID_list:
        queryGetUserID = """
                SELECT id FROM uom.user where email = '""" + eachEmail + """';
            """
        queryGetUserIDResult = dbUtil.execute_query(queryGetUserID)
        logger.info("queryGetUserIDResult [%s] ", queryGetUserIDResult[0]['id'])
        userId = queryGetUserIDResult[0]['id']
        logger.info("userId [%s] ", userId)
        logger.info("Testing Migration for user [%s] ", eachEmail)
        test_migrate_user_site_to_org_in_uomDB(userId, oldOrgId, siteId, newOrgId)
        test_migrate_site_user_roles_authDB(userId)
        logger.info("Testing Migration SUCCESSFUL for user [%s] ", eachEmail)

    logger.info('Execution complete')
    dbUtil.close_connection()

def lambda_handler(event, context):
    #app_role_migration(event)
    #execute_query(event['orgId'])
    #execute_storedproc()

    query = """
    insert ignore into auth.hc_subject_attribute
    select s.id subject_identifier,a.id attribute_id from
    auth.hc_subject s
    join
    (
    select u.id, u.user_name, u.idm_id idm_id, concat(e.entity_type, '-', e1.name, '-', ar.role_code) app_role
    from
    uom.user_entity_app_role uear
    join
    uom.user u on u.id=uear.user_id
    join
    uom.application_role ar on ar.id = uear.app_role_id
    join
    uom.entity e on e.id = uear.entity_id
    join
    uom.application a on a.id=ar.application_id
    join
    uom.entity e1 on e1.id = a.id
    where uear.status='ACTIVE'
    AND e1.name <> 'GE Health Cloud'
    ) uom_user_data on s.subject_identifier=uom_user_data.idm_id
    join
    auth.hc_attribute a
    on a.name='app-role' AND a.value=uom_user_data.app_role
    """
    query2 = """
    insert ignore into auth.hc_subject_attribute
    select s.id subject_identifier,a.id attribute_id from
    auth.hc_subject s
    join
    (
    select u.id, u.user_name, u.idm_id idm_id, concat(e.entity_type, '-', e1.name, '-', ar.role_code) app_role
    from
    uom.user_entity_app_role uear
    join
    uom.user u on u.id=uear.user_id
    join
    uom.application_role ar on ar.id = uear.app_role_id
    join
    uom.entity e on e.id = uear.entity_id
    join
    uom.application a on a.id=ar.application_id
    join
    uom.entity e1 on e1.id = a.id
    where uear.status='ACTIVE'
    AND e1.name = 'GE Health Cloud'
    AND e.entity_type <> 'APP'
    ) uom_user_data on s.subject_identifier=uom_user_data.idm_id
    join
    auth.hc_attribute a
    on a.name='app-role' AND a.value=uom_user_data.app_role
    """
    query3 = """
    insert ignore into auth.hc_subject_attribute
    select s.id subject_identifier,a.id attribute_id from
    auth.hc_subject s
    join
    (
    select u.id, u.user_name, u.idm_id idm_id, concat('HC', '-', e1.name, '-', ar.role_code) app_role
    from
    uom.user_entity_app_role uear
    join
    uom.user u on u.id=uear.user_id
    join
    uom.application_role ar on ar.id = uear.app_role_id
    join
    uom.entity e on e.id = uear.entity_id
    join
    uom.application a on a.id=ar.application_id
    join
    uom.entity e1 on e1.id = a.id
    where uear.status='ACTIVE'
    AND e1.name = 'GE Health Cloud'
    AND e.entity_type = 'APP'
    ) uom_user_data on s.subject_identifier=uom_user_data.idm_id
    join
    auth.hc_attribute a
    on a.name='app-role' AND a.value=uom_user_data.app_role
    """

    isEvent = False if event is None else True
    isAppRole = True if (isEvent is True and 'approle' in event) else False
    isSp = True if (isEvent is True and 'execsp' in event) else False
    isExec = True if (isEvent is True and 'execq' in event) else False
    isDel = True if (isEvent is True and 'delq' in event) else False
    isProdFix = True if (isEvent is True and 'prodfix' in event) else False
    isIPMDel = True if (isEvent is True and 'ipmdelq' in event) else False
    isUpdateEntityName = True if (isEvent is True and 'updentname' in event) else False
    isInternalToExternal = True if (isEvent is True and 'updGrpMembership' in event) else False
    isCheckVersion = True if(isEvent is True and 'checkversion' in event) else False
    isGetApp = True if(isEvent is True and 'getapprole' in event) else False
    isGetAppForUser = True if(isEvent is True and 'getapproleforid' in event) else False
    isGetProcStatus = True if(isEvent is True and 'getprocstatus' in event) else False
    isUpdProcStatus = True if(isEvent is True and 'updprocstatus' in event) else False
    isFixAuth = True if(isEvent is True and 'fixauth' in event) else False
    isUpdateAppRole = True if (isEvent is True and 'updateAppRoleEvent' in event) else False
    disablePatientRole = True if (isEvent is True and 'disablePatientRoleForUser' in event) else False
    getAPIs = True if (isEvent is True and 'getAPIForUser' in event) else False
    getOldOrgs = True if(isEvent is True and 'getOrgs' in event) else False
    getSitesForOrgs = True if(isEvent is True and 'getSites' in event) else False
    migrateSiteRolesForUserAuthDB = True if(isEvent is True and 'migrateSiteRolesAuthDB' in event) else False
    site_to_org_migrationInput = True if (isEvent is True and 'site_to_org_migrationPayload' in event) else False
    test_site_to_org_migrationInput = True if (isEvent is True and 'test_site_to_org_migrationPayload' in event) else False

    if isEvent is True and isAppRole is True:
        app_role_migration(event['approle'])
    elif isEvent is True and isSp is True:
        execute_storedproc()
    elif isEvent is True and isExec is True:
        execute_query(event['execq']);
    elif isEvent is True and isDel is True:
        delete_user(event['delq']);
    elif isEvent is True and isIPMDel is True:
        delete_ipm_roles(event['ipmdelq']);
    elif isEvent is True and isCheckVersion is True:
        check_version()
    elif isEvent is True and isGetAppForUser is True:
        check_application_roles_user(event['getapproleforid'])
    elif isEvent is True and isGetApp is True:
        check_application_roles()
    elif isEvent is True and isGetProcStatus is True:
        select_proxexec_status()
    elif isEvent is True and isFixAuth is True:
        queryId = event['fixauth']
        queryExec = query
        if queryId == 'query1':
            queryExec = query
        if queryId == 'query2':
            queryExec = query2
        if queryId == 'query3':
            queryExec = query3
        logger.info('Executing query \n %s', queryExec)
        fix_auth_db(queryExec)
    elif isEvent is True and isUpdProcStatus is True:
        update_proxexec_status(event['updprocstatus'])
    elif isEvent is True and isUpdateEntityName is True:
        updateEvent = event['updentname']
        if('entityId' in updateEvent and 'entityName' in updateEvent):
            update_entity_name(updateEvent['entityId'],updateEvent['entityName']);
        else:
            logger.error('Not enough parameters...exiting')
    elif isEvent is True and isInternalToExternal is True:
        update_grp_membership(event['updGrpMembership'])
    elif isEvent is True and isProdFix is True:
        prodfix = event['prodfix'];
        if('orgId' in prodfix and 'userId' in prodfix and 'roleName' in prodfix):
            logger.info('User Id '+prodfix['userId'])
            logger.info('Org Id '+prodfix['orgId'])
            logger.info('Role Name '+prodfix['roleName'])
            add_ge_admin_to_org(prodfix['userId'],prodfix['orgId'],prodfix['roleName'])
        else:
            logger.info('Insufficient parameters...exiting')
    elif isEvent is True and isUpdateAppRole is True:
        updateAppRoleEvent = event['updateAppRoleEvent']
        if ('roleId' in updateAppRoleEvent and 'role_display_name' in updateAppRoleEvent):
            logger.info('Role Id ' + updateAppRoleEvent['roleId'])
            logger.info('Role Display Name ' + updateAppRoleEvent['role_display_name'])
            update_app_Role(updateAppRoleEvent['roleId'], updateAppRoleEvent['role_display_name'])
    elif isEvent is True and disablePatientRole is True:
        disablePatientRoleEvent = event['disablePatientRoleForUser']
        if ('emailId' in disablePatientRoleEvent and 'PatientRoleId' in disablePatientRoleEvent):
            logger.info('EmailId is' + disablePatientRoleEvent['emailId'])
            logger.info('PatientRoleId is  ' + disablePatientRoleEvent['PatientRoleId'])
            disable_patient_role_for_user(disablePatientRoleEvent['emailId'], disablePatientRoleEvent['PatientRoleId'])
    elif isEvent is True and getAPIs is True:
        getAPIForUserEvent = event['getAPIForUser']
        if ('user_name' in getAPIForUserEvent):
            logger.info('Username is: ' + getAPIForUserEvent['user_name'])
            get_api_for_user(getAPIForUserEvent['user_name'])
        else:
            logger.info('Insufficient parameters for role update...exiting')
    elif isEvent is True and getOldOrgs is True:
        get_old_orgs()
    elif isEvent is True and getSitesForOrgs is True:
        org_name = event['getSites']
        logger.info('orgname is: ' + org_name['orgid'])
        get_sites_for_orgs(org_name['orgid'])
    elif isEvent is True and migrateSiteRolesForUserAuthDB is True:
        migrateSiteRolesForUserAuthDBEvent = event['migrateSiteRolesAuthDB']
        logger.info('username is: ' + migrateSiteRolesForUserAuthDBEvent['userId'])
        migrate_site_user_roles_authDB(migrateSiteRolesForUserAuthDBEvent['userId'])
    elif isEvent is True and site_to_org_migrationInput is True:
        site_to_org_migrationEvent = event['site_to_org_migrationPayload']
        site_to_org_migration(site_to_org_migrationEvent['emailID_list'], site_to_org_migrationEvent['oldOrgId'], site_to_org_migrationEvent['siteId'], site_to_org_migrationEvent['newOrgId'])
    elif isEvent is True and test_site_to_org_migrationInput is True:
        test_site_to_org_migrationEvent = event['test_site_to_org_migrationPayload']
        test_site_to_org_migration(test_site_to_org_migrationEvent['emailID_list'],test_site_to_org_migrationEvent['oldOrgId'], test_site_to_org_migrationEvent['siteId'], test_site_to_org_migrationEvent['newOrgId'])
    else:
        logger.info('No parameters passed...exiting')


if __name__ == '__main__':
    if len(argv) != 2:
        event = None
    else:
        try:
            event = json.loads(argv[1])
        except Exception:
            logger.warning('Cannot parse the event JSON [%s], Suppressing error, setting event as None', argv[1])
            event = None
    lambda_handler(event,None)
