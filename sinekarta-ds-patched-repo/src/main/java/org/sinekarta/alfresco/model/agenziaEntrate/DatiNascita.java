//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-558 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.11.27 at 11:03:36 AM CET 
//


package org.sinekarta.alfresco.model.agenziaEntrate;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{}ComuneStato"/>
 *         &lt;element ref="{}SiglaProvincia"/>
 *         &lt;element ref="{}Data"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "comuneStato",
    "siglaProvincia",
    "data"
})
@XmlRootElement(name = "DatiNascita")
public class DatiNascita implements Serializable {

	private static final long serialVersionUID = 1L;
	
    @XmlElement(name = "ComuneStato", required = true)
    protected String comuneStato;
    @XmlElement(name = "SiglaProvincia", required = true)
    protected String siglaProvincia;
    @XmlElement(name = "Data", required = true)
    protected Data data;

    /**
     * Gets the value of the comuneStato property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getComuneStato() {
        return comuneStato;
    }

    /**
     * Sets the value of the comuneStato property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setComuneStato(String value) {
        this.comuneStato = value;
    }

    /**
     * Gets the value of the siglaProvincia property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSiglaProvincia() {
        return siglaProvincia;
    }

    /**
     * Sets the value of the siglaProvincia property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSiglaProvincia(String value) {
        this.siglaProvincia = value;
    }

    /**
     * Gets the value of the data property.
     * 
     * @return
     *     possible object is
     *     {@link Data }
     *     
     */
    public Data getData() {
        return data;
    }

    /**
     * Sets the value of the data property.
     * 
     * @param value
     *     allowed object is
     *     {@link Data }
     *     
     */
    public void setData(Data value) {
        this.data = value;
    }

}
