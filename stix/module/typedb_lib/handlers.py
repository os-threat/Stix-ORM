import traceback

from returns.pipeline import is_successful
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def handle_result(result,
                  name: str = '',
                  strict_failure: bool = False):
        result_failure = not is_successful(result)
        try:
            if result_failure:
                logger.info("Failure in result for: "+ name)
                logging.exception("\n".join(traceback.format_exception(result.failure())))
        except Exception as e:
            logger.error(e)
        if strict_failure and result_failure:
            raise Exception(str(result.failure()))

def handle_missing_values(result_failure: bool,
                  name: str = '',
                  strict_failure: bool = False):

    try:
        if result_failure:
            logger.error(name)
    except Exception as e:
        logger.error(e)
    if strict_failure and result_failure:
        raise Exception(name)