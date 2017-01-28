<?php
namespace packages\whois;
class org_za_handler {

    function parse($data, $query) {
        $items = array(
            'domain.status' => 'Status:',
            'domain.nserver' => 'Domain name servers in listed order:',
            'domain.changed' => 'Record last updated on',
            'owner' => 'rwhois search on',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            '#' => 'Search Again'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data['rawdata'], $items);

        if (isset($r['regrinfo']['domain']['status'])) {
            $r['regrinfo']['registered'] = 'yes';
            $r['regrinfo']['domain']['handler'] = strtok(array_shift($r['regrinfo']['owner']), ' ');
            $r['regrinfo'] = get_contacts($r['regrinfo']);
        } else
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo']['referrer'] = 'http://www.org.za';
        $r['regyinfo']['registrar'] = 'The ORG.ZA Domain';
        return $r;
    }

}
