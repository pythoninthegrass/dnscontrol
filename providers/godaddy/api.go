package godaddy

import (
	"context"
	"fmt"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/pkg/printer"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/oze4/godaddygo"
)

type godaddyProvider struct {
	apiKey    string
	apiSecret string
}

func (api *godaddyProvider) create(rc *models.RecordConfig, domain string) error {
	fmt.Printf("Create record %s of type %s with data: %s\n", rc.Name, rc.Type, rc.GetTargetField())
	if rc.TTL < 600 {
		printer.Warnf("GoDaddy does not support TTL lower than 600, changing %d to 600\n", rc.TTL)
		rc.TTL = 600
	}

	newRecord := godaddygo.Record{
		Name:     rc.Name,
		Type:     StringToRecordType(rc.Type),
		Port:     int(rc.SrvPort),
		Priority: int(rc.SrvPriority),
		TTL:      int(rc.TTL),
		Weight:   int(rc.SrvWeight),
	}

	if newRecord.Type != "TXT" {
		newRecord.Data = rc.GetTargetField()
	} else {
		newRecord.Data = rc.GetTargetTXTJoined()
	}

	records, err := api.getRecordsForDomain(domain)
	if err != nil {
		return err
	}

	newRecords := []godaddygo.Record{newRecord}
	err = records.Add(context.Background(), newRecords)
	if err != nil {
		fmt.Printf("ERROR!!!!!!!")
		return err
	}

	return nil
}

func (api *godaddyProvider) delete(rc *models.RecordConfig, domain string) error {
	fmt.Printf("Delete record: %s of type %s with data: %s\n", rc.Name, rc.Type, rc.GetTargetField())

	records, err := api.getRecordsForDomain(domain)
	if err != nil {
		printer.Errorf("Failed getting records for domain %s: %s", domain, err)
		return err
	}

	recordList, err := records.List(context.Background())
	if err != nil {
		printer.Errorf("Failed converting records to a list: %s", err)
		return err
	}

	//fmt.Printf("Trying to find match for deletion in %d records\n", len(recordList))
	if rc.TTL < 600 {
		printer.Warnf("Trying to delete a record with TTL %d, GoDaddy does not support TTL lower than 600", rc.TTL)
		rc.TTL = 600
	}

	for _, goDaddyRecord := range recordList {
		if IsMatch(goDaddyRecord, rc, domain) {
			printer.Debugf("Found matching record to delete, Name: %s | Type: %s | Value: %s", rc.Name, rc.Type, rc.GetTargetField())
			err := records.Delete(context.Background(), goDaddyRecord)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (api *godaddyProvider) update(oldRecord *models.RecordConfig, newRecord *models.RecordConfig, domain string) error {
	fmt.Println("Printing oldRecord")
	fmt.Printf("Name: %s\n", oldRecord.Name)
	fmt.Printf("Type: %s\n", oldRecord.Type)
	fmt.Printf("TTL: %d\n", oldRecord.TTL)
	fmt.Printf("Value: %s\n", oldRecord.GetTargetField())

	fmt.Println("Printing newRecord")
	fmt.Printf("Name: %s\n", newRecord.Name)
	fmt.Printf("Type: %s\n", newRecord.Type)
	fmt.Printf("TTL: %d\n", newRecord.TTL)
	fmt.Printf("Value: %s\n", newRecord.GetTargetField())

	err := api.delete(oldRecord, domain)
	if err != nil {
		return err
	}

	err = api.create(newRecord, domain)
	if err != nil {
		return err
	}
	return nil
}

func (api *godaddyProvider) getNameserversForDomain(domain string) ([]*models.Nameserver, error) {
	records, err := api.getRecordsForDomain(domain)
	if err != nil {
		return nil, err
	}

	nameservers, err := records.FindByType(context.Background(), godaddygo.RecordTypeNS)
	if err != nil {
		return nil, err
	}

	tmpArray := make([]string, len(nameservers))
	for i, s := range nameservers {
		tmpArray[i] = s.Data
	}
	return models.ToNameservers(tmpArray)
}

func (api *godaddyProvider) getAll(domain string) (models.Records, error) {
	records, err := api.getRecordsForDomain(domain)
	if err != nil {
		return nil, err
	}

	recordList, err := records.List(context.Background())
	if err != nil {
		return nil, err
	}

	tmpArray := []*models.RecordConfig{}
	for _, goDaddyRecord := range recordList {
		//Edits to NS records are not allowed, do not pass them
		if goDaddyRecord.Type.String() == "NS" {
			continue
		}
		r := &models.RecordConfig{
			Type:      strings.TrimSpace(goDaddyRecord.Type.String()),
			TTL:       uint32(goDaddyRecord.TTL),
			SrvWeight: uint16(goDaddyRecord.Weight),
			SrvPort:   uint16(goDaddyRecord.Port),
		}
		if r.Type == "TXT" {
			r.SetTargetTXT(goDaddyRecord.Data)
		} else if r.Type == "MX" {
			r.SetTargetMX((uint16(goDaddyRecord.Priority)), goDaddyRecord.Data)
		} else {
			fmt.Printf("Setting Target to: %s\n", goDaddyRecord.Data)
			r.SetTarget(goDaddyRecord.Data)
		}
		fmt.Printf("Setting label to: %s\n", goDaddyRecord.Name)
		r.SetLabel(goDaddyRecord.Name, domain)
		tmpArray = append(tmpArray, r)
	}

	returnRecords := models.Records{}
	for _, recordConfig := range tmpArray {
		//fmt.Printf("Found record %s of type %s with value %s and TTL %d\n", recordConfig.Name, recordConfig.Type, recordConfig.GetTargetField(), recordConfig.TTL)
		returnRecords = append(returnRecords, recordConfig)
	}
	return returnRecords, nil
}

func (api *godaddyProvider) getRecordsForDomain(domain string) (godaddygo.Records, error) {
	godaddyDomain, err := api.getGoDaddyApi(domain)
	if err != nil {
		return nil, err
	}
	return godaddyDomain.Records(), nil
}

func (api *godaddyProvider) getGoDaddyApi(domain string) (godaddygo.Domain, error) {
	apiEndpoint, err := godaddygo.NewProduction(api.apiKey, api.apiSecret)
	if err != nil {
		return nil, err
	}

	godaddy := apiEndpoint.V1() // Target version 1 of the production API
	return godaddy.Domain(domain), nil
}

func StringToRecordType(s string) godaddygo.RecordType {
	switch strings.TrimSpace(s) {
	case "A":
		return godaddygo.RecordTypeA
	case "AAAA":
		return godaddygo.RecordTypeAAAA
	case "CNAME":
		return godaddygo.RecordTypeCNAME
	case "MX":
		return godaddygo.RecordTypeMX
	case "NS":
		return godaddygo.RecordTypeNS
	case "SOA":
		return godaddygo.RecordTypeSOA
	case "SRV":
		return godaddygo.RecordTypeSRV
	case "TXT":
		return godaddygo.RecordTypeTXT
	default:
		return ""
	}
}

func IsMatch(goDaddyRecord godaddygo.Record, rc *models.RecordConfig, domain string) bool {
	name := rc.Name
	if goDaddyRecord.Name != name || goDaddyRecord.Type.String() != rc.Type || goDaddyRecord.TTL != int(rc.TTL) {
		return false
	}

	var value = rc.GetTargetField()
	if rc.Type == "TXT" {
		value = rc.GetTargetTXTJoined()
	}

	suffix := "." + domain + "."
	if strings.HasSuffix(value, suffix) {
		value = strings.TrimSuffix(value, suffix)
	}

	if goDaddyRecord.Data != value {
		return false
	}
	return true
}
