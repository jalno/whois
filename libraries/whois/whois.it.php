<?php
namespace packages\whois;
/**
 * @todo BUG
 * - nserver -> array
 * - ContactID in address
 */
class it_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain.name' => 'Domain:',
            'domain.nserver' => 'Nameservers',
            'domain.status' => 'Status:',
            'domain.expires' => 'Expire Date:',
            'owner' => 'Registrant',
            'admin' => 'Admin Contact',
            'tech' => 'Technical Contacts',
            'registrar' => 'Registrar'
        );

        $extra = array(
            'address:' => 'address.',
            'contactid:' => 'handle',
            'organization:' => 'organization',
            'created:' => 'created',
            'last update:' => 'changed',
            'web:' => 'web'
        );

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'ymd', $extra);

        if (isset($r['regrinfo']['registrar'])) {
            $r['regrinfo']['domain']['registrar'] = $r['regrinfo']['registrar'];
            unset($r['regrinfo']['registrar']);
        }

        $r['regyinfo'] = array(
            'registrar' => 'IT-Nic',
            'referrer' => 'http://www.nic.it/'
        );
        return $r;
    }

}
