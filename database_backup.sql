--
-- PostgreSQL database dump
--

\restrict UsxdgUuJL4hYqsx7uebyRz7uVQC18oitD7G5lFm3KxpaSsCQzeqMzmG2dttkGq7

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: onu_devices; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.onu_devices (
    id integer NOT NULL,
    olt_name character varying(100) NOT NULL,
    customer_name character varying(150) NOT NULL,
    description character varying(255),
    pppoe_user character varying(100),
    gpon_port character varying(50) NOT NULL,
    status character varying(50),
    rx_olt double precision,
    rx_onu double precision,
    sn_mac character varying(50),
    actual_type character varying(50),
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.onu_devices OWNER TO postgres;

--
-- Name: onu_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.onu_devices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.onu_devices_id_seq OWNER TO postgres;

--
-- Name: onu_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.onu_devices_id_seq OWNED BY public.onu_devices.id;


--
-- Name: onu_devices id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.onu_devices ALTER COLUMN id SET DEFAULT nextval('public.onu_devices_id_seq'::regclass);


--
-- Data for Name: onu_devices; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.onu_devices (id, olt_name, customer_name, description, pppoe_user, gpon_port, status, rx_olt, rx_onu, sn_mac, actual_type, created_at) FROM stdin;
1	OLT-C300 Tajur	KP.AHSDHASUD	jalan kp. rawa bogo	asds	1/1/3:1	Online	-22.45	-21.15	ZTEASCAEQEQ	F660	2026-09-26 13:48:47.094641+07
\.


--
-- Name: onu_devices_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.onu_devices_id_seq', 1, true);


--
-- Name: onu_devices onu_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.onu_devices
    ADD CONSTRAINT onu_devices_pkey PRIMARY KEY (id);


--
-- Name: ix_onu_devices_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_onu_devices_id ON public.onu_devices USING btree (id);


--
-- Name: ix_onu_devices_sn_mac; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ix_onu_devices_sn_mac ON public.onu_devices USING btree (sn_mac);


--
-- PostgreSQL database dump complete
--

\unrestrict UsxdgUuJL4hYqsx7uebyRz7uVQC18oitD7G5lFm3KxpaSsCQzeqMzmG2dttkGq7

