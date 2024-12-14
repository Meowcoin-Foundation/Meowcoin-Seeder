""" Cloudflare interface """
import logging
import cloudflare
import errors
import string

logger = logging.getLogger(__name__)


def isipv6(ip):

    """ Extremely naive IPV6 check. """

    return ip.count(':') > 1

def _lookup_zone_id(cloudflare, domain):

    """ Return the zone_id for a given domain using the cloudflare interface. """

    logger.info("Resolving cloudflare zoneid for domain name: ".format(domain))
    zones = cloudflare.zones.list()
    for zone in zones:
        if zone.name == domain:
            return zone.id
    raise errors.ZoneNotFound(f"Zone not found for domain: {domain}")

class CloudflareSeeder(object):

    """ Cloudflare abstraction layer allowing to manage DNS entries. """

    @staticmethod
    def from_configuration(configuration):

        """" Instantiate and return an instance from a configuration dict. """

        logger.debug("Creating CloudflareSeeder interface from configuration.")

        user = configuration['cf_username'].replace('"', '')
        key = configuration['cf_api_key'].replace('"', '')
        domain = configuration['cf_domain'].replace('"', '')
        name = configuration['cf_domain_prefix'].replace('"', '')

        return CloudflareSeeder(user, key, domain, name)

    def __init__(self, user, key, domain, name):

        """ Constructor: set the member variables. """

        logger.debug("CloudflareSeeder creation for user: {} domain: {} name: {}".format(user, domain, name))
        self.cf = cloudflare.Cloudflare(api_email=user, api_key=key)
        self.domain = domain
        self.name = name
        self._zone_id = None

    @property
    def zone_id(self):

        """ Resolve the zone id from the name if we haven't before. If we have, just return it. """

        if self._zone_id is None:
            self._zone_id = _lookup_zone_id(self.cf, self.domain)

        return self._zone_id

    def get_seed_records(self):
        zone_id = self.zone_id
        dns_records = self.cf.dns.records.list(zone_id=zone_id)
        return dns_records

    def get_seeds(self):

        """ Read the seeds for the zone and name in cloudflare. """

        logger.debug("Getting seeds from cloudflare")
        return [record.content for record in self.get_seed_records()]

    def _set_seed(self, seed, ttl=None, flags=False):

        """ Set either a flags or no flags seed entry in cloud flare. """

        logger.debug("Setting seed {} in cloudflare".format(seed))
        new_record = {
            'name': self.name if not flags else 'x9.' + self.name,
            'type': 'AAAA' if isipv6(seed) else 'A',
            'content': seed
        }

        if ttl is not None:
            new_record['ttl'] = ttl

        logger.debug("Posting record {}".format(new_record))
        try:
            self.cf.dns.records.create(zone_id=self.zone_id, **new_record)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            logger.error("Error setting seed through the cloudflare API: %d %s" % (e, e))

    def set_seed(self, seed, ttl=None):

        """ Add a new seed record to cloudflare with corresponding flagged entry. """

        self._set_seed(seed, ttl=ttl)
        self._set_seed(seed, ttl=ttl, flags=True)

    def delete_seeds(self, seeds):

        """ Delete the seeds' DNS entries in cloudflare. """

        logger.debug("Deleting seeds from cloudflare.")
        for seed_record in self.get_seed_records():
            if seed_record.content in seeds:
                logger.debug("Found seed to delete: {}".format(seed_record.content))
                self.cf.dns.records.delete(seed_record.id, zone_id=self.zone_id)

    def set_seeds(self, seeds, ttl=None):

        """ Set a list of seeds as DNS entries in cloudflare. """

        for seed in seeds:
            self.set_seed(seed, ttl)
