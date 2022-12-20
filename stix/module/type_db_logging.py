from returns.pipeline import is_successful
import logging

from returns.result import safe

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def log_delete_layers(result):
    try:
        if is_successful(result):
            logger.debug("Successfully deleted layer")
        else:
            logger.debug("Failed to delete layers")
            logger.error(str(result.failure()))
    except Exception as e:
        logger.error(e)

def log_delete_layer(result, layer):
    try:
        if not is_successful(result):
            logger.debug("Failed to delete layer")
            logger.error(str(result.failure()))
            logger.debug(layer)
    except Exception as e:
        logger.error(e)

def log_add_layer(result, layer):
    try:
        if not is_successful(result):
            logger.debug("Failed to add layer")
            logger.error(str(result.failure()))
            logger.debug(layer)
    except Exception as e:
        logger.error(e)

def log_insert_query(result, layer):
    try:
        if not is_successful(result):
            logger.debug("Failed to creare insert query")
            logger.error(str(result.failure()))
            logger.debug(layer)
    except Exception as e:
        logger.error(e)

def log_delete_instruction_update_layer(result):
    try:
        if not is_successful(result):
            logger.debug("Failed to update layer")
            logger.error(str(result.failure()))
    except Exception as e:
        logger.error(e)

def log_add_instruction_update_layer(result):
    try:
        if not is_successful(result):
            logger.debug("Failed to update layer")
            logger.error(str(result.failure()))
    except Exception as e:
        logger.error(e)


def log_delete_instruction_outcome(result):
    try:
        logger.debug("=========================== delete typeql instruction ====================================")
        if is_successful(result):
            logger.debug("Successfully added instruction")

        else:
            logger.debug("Failed to add the instruction")
            logger.error(str(result.failure()))
        logger.debug("============================================================================================")

    except Exception as e:
        logger.error(e)

def log_delete_instruction(dep_match,
                           dep_insert,
                           indep_ql,
                           dep_obj,
                           del_match,
                           del_tql):
    try:
        logger.debug(' ---------------------------Delete Object----------------------')
        logger.debug(f'dep_match -> {dep_match}\n dep_insert -> {dep_insert}')
        logger.debug(f'indep_ql -> {indep_ql}\n dep_obj -> {dep_obj}')
        logger.debug("=========================== delete typeql below ====================================")
        logger.debug(f'del_match -> {del_match}\n del_tql -> {del_tql}')
    except Exception as e:
        logger.error(e)
