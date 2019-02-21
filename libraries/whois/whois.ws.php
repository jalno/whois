<?php
namespace packages\whois;
use packages\whois\WhoisClient;
class ws_handler extends WhoisClient {

    function parse($data_str, $query) {
        $items = array(
            'Domain Name:' => 'domain.name',
            'Registrant Name:' => 'owner.organization',
            'Registrant Email:' => 'owner.email',
            'Domain Created:' => 'domain.created',
            'Domain Last Updated:' => 'domain.changed',
            'Registrar Name:' => 'domain.sponsor',
            'Current Nameservers:' => 'domain.nserver.',
            'Administrative Contact Email:' => 'admin.email',
            'Administrative Contact Telephone:' => 'admin.phone',
            'Registrar Whois:' => 'rwhois'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'ymd');

        $r['regyinfo']['referrer'] = 'http://www.samoanic.ws';
        $r['regyinfo']['registrar'] = 'Samoa Nic';

        if (!empty($r['regrinfo']['domain']['name'])) {
            $r['regrinfo']['registered'] = 'yes';

            if (isset($r['regrinfo']['rwhois'])) {
                if ($this->deepWhois) {
                    $r['regyinfo']['whois'] = $r['regrinfo']['rwhois'];
                    $r = $this->deepWhois($query, $r);
                }

                unset($r['regrinfo']['rwhois']);
            }
        } else
            $r['regrinfo']['registered'] = 'no';

        return $r;
    }
}
