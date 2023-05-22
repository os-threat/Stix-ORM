"""Utilities for generating SQL while avoiding SQL injection vulns"""
import re


COMP_OPS = ['=', '<>', '!=', '<', '>', '<=', '>=',
            'LIKE', 'IN', 'IS', 'NOT LIKE', 'NOT IN', 'IS NOT']
PRED_OPS = ['AND', 'OR']
JOIN_TYPES = ['INNER', 'OUTER', 'LEFT OUTER', 'CROSS']
AGG_FUNCS = ['COUNT', 'SUM', 'MIN', 'MAX', 'AVG', 'NUNIQUE']
COL_PATTERN = r"^(\*|[A-Za-z_]+)$"


def _quote(obj):
    """Double-quote an SQL identifier if necessary"""
    if isinstance(obj, str):
        if obj == '*':
            return obj
        return f'"{obj}"'
    return str(obj)


def _alias(obj):
    if hasattr(obj, 'alias') and obj.alias:
        return _quote(obj.alias)
    return _quote(obj)
