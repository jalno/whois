<?php
namespace packages\whois;
class lu_handler {

    function parse($data_str, $query) {
        $items = array(
            'domainname:' => 'domain.name',
            'domaintype:' => 'domain.status',
            'nserver:' => 'domain.nserver.',
            'registered:' => 'domain.created',
            'source:' => 'domain.source',
            'ownertype:' => 'owner.type',
            'org-name:' => 'owner.organization',
            'org-address:' => 'owner.address.',
            'org-zipcode:' => 'owner.address.pcode',
            'org-city:' => 'owner.address.city',
            'org-country:' => 'owner.address.country',
            'adm-name:' => 'admin.name',
            'adm-address:' => 'admin.address.',
            'adm-zipcode:' => 'admin.address.pcode',
            'adm-city:' => 'admin.address.city',
            'adm-country:' => 'admin.address.country',
            'adm-email:' => 'admin.email',
            'tec-name:' => 'tech.name',
            'tec-address:' => 'tech.address.',
            'tec-zipcode:' => 'tech.address.pcode',
            'tec-city:' => 'tech.address.city',
            'tec-country:' => 'tech.address.country',
            'tec-email:' => 'tech.email',
            'bil-name:' => 'billing.name',
            'bil-address:' => 'billing.address.',
            'bil-zipcode:' => 'billing.address.pcode',
            'bil-city:' => 'billing.address.city',
            'bil-country:' => 'billing.address.country',
            'bil-email:' => 'billing.email'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'dmy');

        $r['regyinfo'] = array(
            'referrer' => 'http://www.dns.lu',
            'registrar' => 'DNS-LU'
        );
        return $r;
    }

}
