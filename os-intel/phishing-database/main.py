import requests
import ipaddress
import validators
from stix2 import Bundle, Identity, Indicator, IPv4Address,IPv6Address, Relationship, DomainName, URL, ObservedData
from stix2 import utils
from stix2.exceptions import InvalidValueError
import logging

logger = logging.getLogger()


'''
Load all the STIX objects from that Phishing Database
Pleaes note that Observed-Data can only reference SRO and SCO but NOT Indicators.
Indicators needs to be referenced via additional SRO.
'''
class Loader():
    ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'

    def __init__(self):
        self.author = Identity(
            name="Phishing Database",
            identity_class="organization",
        )
    def get_IP_phish(self,add_indicators=False)->Bundle:

        observables = []
        indicators = []

        total = 0

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:

                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr)>0:
                        try:
                            if validators.ip_address.ipv4(ipstr):
                                observable = IPv4Address(value=ipstr)
                                observables.append(observable)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv4:value = '{observable.value}']",
                                    labels=["phishing"],
                                )
                                indicators.append(indicator)
                            elif validators.ip_address.ipv6(ipstr):
                                observable = IPv6Address(value=ipstr)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv6:value = '{observable.value}']",
                                    labels=["phishing",status],
                                )
                            total+=1
                        except Exception as e:
                            logger.error(f"Invalid IP address {ipstr}")

            else:
                raise Exception('Feed URL is down')

        assert total > 0
        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs=observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

    def get_domain_phish(self,add_indicators=False):

        observables = []
        indicators = []

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'Domain {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-domains-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    domain = line.strip()
                    if len(domain)>0 and validators.domain(domain):
                        total+=1
                        observable = DomainName(value=domain)
                        observables.append(observable)
                        indicator = Indicator(
                            name=domain,
                            description="Phishing Domain",
                            created_by_ref=f"{self.author.id}",
                            pattern_type="stix",
                            pattern=f"[domain:value = '{domain}']",
                            labels=["phishing",status],
                        )
                        indicators.append(indicator)

            else:
                raise Exception('Feed URL is down')

        assert total>0

        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs= observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

    def get_links_phish(self,add_indicators=False):
        observables = []
        indicators = []

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'URL {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-links-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    url = line.strip()
                    if len(url)>0 and validators.url(url):
                        total+=1
                        observable = URL(value=url)
                        observables.append(observable)

                        try:
                            indicator = Indicator(
                                name=url,
                                description="Phishing URL",
                                created_by_ref=f"{self.author.id}",
                                pattern_type="stix",
                                pattern=f"[url:value = '{url}']",
                                labels=["phishing",status],
                            )
                            indicators.append(indicator)
                        except InvalidValueError as ver:
                            logger.error(f'Invalid PATTERN for URL '
                                         f'{url}')
            else:
                raise Exception('Feed URL is down')

        assert total>0

        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs= observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

import pathlib


def full_load():

    # create a bundle to save the observation data
    folder = pathlib.Path(__file__).resolve().parent
    folder = folder/"data"/"bundles"
    folder.mkdir(parents=True, exist_ok=True)

    loader = Loader()

    # IP address
    bundle = loader.get_IP_phish()

    file_path = folder / "phishing-ip-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_IP_phish(add_indicators=True)

    file_path = folder / "phishing-ip-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    # DOMAIN
    bundle = loader.get_domain_phish()

    file_path = folder / "phishing-domain-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_domain_phish(add_indicators=True)

    file_path = folder / "phishing-domain-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    # URL

    bundle = loader.get_links_phish()

    file_path = folder / "phishing-url-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_links_phish(add_indicators=True)

    file_path = folder / "phishing-url-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

from stixorm.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.definitions.os_threat import Feed, Feeds, ThreatSubObject
from stixorm.module.typedb_lib.instructions import ResultStatus
from stix2.v21.common import ExternalReference,MarkingDefinition,StatementMarking
import sqlite3
def load_ip_feed():
    loader = Loader()

    # IP address
    bundle = loader.get_IP_phish()

    return bundle

if __name__ == '__main__':
    # define the database data and import details
    connection = {
        "uri": "localhost",
        "port": "1729",
        "database": "stix",
        "user": None,
        "password": None
    }

    import_type = import_type_factory.get_all_imports()

    typedb_source = TypeDBSource(connection, import_type)
    typedb_sink = TypeDBSink(connection, True, import_type)

    ip_a = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

    ip_ia = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-INACTIVE.txt")

    ip_in = ExternalReference(source_name="Phishing Database ACTIVE",
                             external_id="phishing-IPs-ACTIVE.txt",
                             url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-INVALID.txt")

    marking_def_statement = MarkingDefinition(
        definition_type="statement",
        definition=StatementMarking("Phishing Database...")
    )
    # create the Feeds object
    feeds = Feeds(name='phishing-db',
                  description="the phishing database",
                  paid=False,
                  free=True,
                  labels=["active","inactive","invalid","ip"],
                  lang="en",
                  external_references=[ip_a,ip_ia,ip_in],
                  object_marking_refs = [marking_def_statement],
                  contained=[])

    results = typedb_sink.add(feeds)

    for result in results:
        print(f"Status = {result.status} ID = {result.id} Error = {result.error}")



