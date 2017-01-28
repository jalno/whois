<?php
namespace packages\whois;
class eu_handler {

    function parse($data, $query) {

        $items = array(
            'domain.name' => 'Domain:',
            'domain.status' => 'Status:',
            'domain.nserver' => 'Name servers:',
            'domain.created' => 'Registered:',
            'domain.registrar' => 'Registrar:',
            'tech' => 'Registrar Technical Contacts:',
            'owner' => 'Registrant:',
            '' => 'Please visit'
        );

        $extra = array(
            'organisation:' => 'organization',
            'website:' => 'url'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data['rawdata'], $items);

        if (!empty($r['regrinfo']['domain']['status']))
            switch ($r['regrinfo']['domain']['status']) {
                case 'FREE':
                case 'AVAILABLE':
                    $r['regrinfo']['registered'] = 'no';
                    break;

                case 'APPLICATION PENDING':
                    $r['regrinfo']['registered'] = 'pending';
                    break;

                default:
                    $r['regrinfo']['registered'] = 'unknown';
            } else
            $r['regrinfo']['registered'] = 'yes';

        if (isset($r['regrinfo']['tech']))
            $r['regrinfo']['tech'] = get_contact($r['regrinfo']['tech'], $extra);

        if (isset($r['regrinfo']['domain']['registrar']))
            $r['regrinfo']['domain']['registrar'] = get_contact($r['regrinfo']['domain']['registrar'], $extra);

        $r['regyinfo']['referrer'] = 'http://www.eurid.eu';
        $r['regyinfo']['registrar'] = 'EURID';
        return $r;
    }

}
