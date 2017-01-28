<?php
namespace packages\whois;
class arin_handler {

    function parse($data_str, $query) {
        $items = array(
            'OrgName:' => 'owner.organization',
            'CustName:' => 'owner.organization',
            'OrgId:' => 'owner.handle',
            'Address:' => 'owner.address.street.',
            'City:' => 'owner.address.city',
            'StateProv:' => 'owner.address.state',
            'PostalCode:' => 'owner.address.pcode',
            'Country:' => 'owner.address.country',
            'NetRange:' => 'network.inetnum',
            'NetName:' => 'network.name',
            'NetHandle:' => 'network.handle',
            'NetType:' => 'network.status',
            'NameServer:' => 'network.nserver.',
            'Comment:' => 'network.desc.',
            'RegDate:' => 'network.created',
            'Updated:' => 'network.changed',
            'ASHandle:' => 'network.handle',
            'ASName:' => 'network.name',
            'NetHandle:' => 'network.handle',
            'NetName:' => 'network.name',
            'TechHandle:' => 'tech.handle',
            'TechName:' => 'tech.name',
            'TechPhone:' => 'tech.phone',
            'TechEmail:' => 'tech.email',
            'OrgAbuseName:' => 'abuse.name',
            'OrgAbuseHandle:' => 'abuse.handle',
            'OrgAbusePhone:' => 'abuse.phone',
            'OrgAbuseEmail:' => 'abuse.email.',
            'ReferralServer:' => 'rwhois'
        );

        $r = generic_parser_b($data_str, $items, 'ymd', false, true);

        if (@isset($r['abuse']['email']))
            $r['abuse']['email'] = implode(',', $r['abuse']['email']);

        return array('regrinfo' => $r);
    }

}
