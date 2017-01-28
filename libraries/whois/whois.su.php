<?php
namespace packages\whois;
class su_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain:' => 'domain.name',
            'registrar:' => 'domain.sponsor',
            'state:' => 'domain.status',
            'person:' => 'owner.name',
            'phone:' => 'owner.phone',
            'e-mail:' => 'owner.email',
            'created:' => 'domain.created',
            'paid-till:' => 'domain.expires',
                /*
                  'nserver:' => 'domain.nserver.',
                  'source:' => 'domain.source',
                  'type:' => 'owner.type',
                  'org:' => 'owner.organization',
                  'fax-no:' => 'owner.fax',
                 */
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'dmy');

        $r['regyinfo'] = array(
            'referrer' => 'http://www.ripn.net',
            'registrar' => 'RUCENTER-REG-RIPN'
        );
        return $r;
    }

}
